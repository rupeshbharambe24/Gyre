//! **`gyre-origin`** — a protected origin that reaches clients through the guarded relay
//! *without publishing any inbound address*.
//!
//! It dials *out* to a `gyre-rendezvous` relay, solves the admission puzzle, parks behind a
//! shared cookie, and answers one request; then it re-parks for the next. It never binds a
//! listener, so there is no origin IP anywhere for a volumetric attacker to target — the
//! whole point of the onion-service model.
//!
//! ```text
//! gyre-origin --rendezvous 127.0.0.1:9500 --cookie my-service --reply "origin says"
//! ```
//!
//! This is a demonstration service (it echoes the request back with a prefix). A real origin
//! would run its own application over the spliced, end-to-end-encrypted stream — the relay
//! only ever copies opaque bytes.

use std::net::SocketAddr;
use std::process::ExitCode;

use gyre_cli::{flag, obfuscator, Session};
use gyre_net::{read_frame_obfuscated, write_frame_obfuscated};
use gyre_shield::rendezvous::dial_admitted;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let Some(rzv) = flag(&args, "--rendezvous") else {
        eprintln!("gyre-origin: --rendezvous host:port is required");
        return ExitCode::FAILURE;
    };
    let Ok(rzv): Result<SocketAddr, _> = rzv.parse() else {
        eprintln!("gyre-origin: bad --rendezvous address {rzv:?}");
        return ExitCode::FAILURE;
    };
    let cookie = flag(&args, "--cookie").unwrap_or_else(|| "gyre-service".to_string());
    let reply_prefix = flag(&args, "--reply").unwrap_or_else(|| "origin answers".to_string());

    // The payload disguise, keyed from the cookie. Must match the client's --obfs.
    let obfs_name = flag(&args, "--obfs").unwrap_or_else(|| "identity".to_string());
    let obfs = match obfuscator(&obfs_name, cookie.as_bytes()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("gyre-origin: {e}");
            return ExitCode::FAILURE;
        }
    };

    // With --forward-secret, use a compartmentalized, forward-secret session for the payload
    // instead of a flat transport key. Must match the client's --forward-secret and --context.
    let forward_secret = args.iter().any(|a| a == "--forward-secret");
    let context = flag(&args, "--context").unwrap_or_else(|| "default".to_string());

    let mode = if forward_secret {
        format!("forward-secret session, context {context:?}")
    } else {
        format!("transport {obfs_name}")
    };
    println!(
        "gyre-origin: no inbound address; reaching clients via rendezvous {rzv} under cookie {cookie:?} ({mode})"
    );

    // Serve until killed: park, answer one request, re-park. Each park re-solves the
    // admission puzzle, so an origin costs work to (re)appear just as a client does.
    loop {
        let mut stream = match dial_admitted(rzv, cookie.as_bytes()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("gyre-origin: could not park at {rzv}: {e}");
                return ExitCode::FAILURE;
            }
        };

        // A fresh session per park (so keys never repeat across clients).
        let mut session = forward_secret.then(|| Session::new(cookie.as_bytes(), &context, false));

        let request = if let Some(s) = session.as_mut() {
            s.recv(&mut stream).await
        } else {
            read_frame_obfuscated(&mut stream, obfs.as_ref()).await
        };

        match request {
            Ok(Some(request)) => {
                let mut response = reply_prefix.clone().into_bytes();
                response.extend_from_slice(b": ");
                response.extend_from_slice(&request);
                let sent = if let Some(s) = session.as_mut() {
                    s.send(&mut stream, &response).await
                } else {
                    write_frame_obfuscated(&mut stream, obfs.as_ref(), &response).await
                };
                if let Err(e) = sent {
                    eprintln!("gyre-origin: reply failed: {e}");
                }
                println!(
                    "  served a request ({} bytes) and re-parking",
                    request.len()
                );
            }
            Ok(None) => { /* peer went away before sending; re-park */ }
            Err(e) => eprintln!("gyre-origin: read error: {e}"),
        }
    }
}
