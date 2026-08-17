//! **`gyre-origin`** — a protected origin that reaches clients through the guarded relay(s)
//! *without publishing any inbound address*.
//!
//! It dials *out* to one or more `gyre-rendezvous` relays, solves the admission puzzle, parks
//! behind a shared cookie, and answers requests. It never binds a listener, so there is no
//! origin IP anywhere for a volumetric attacker to target — the onion-service model.
//!
//! ```text
//! gyre-origin --rendezvous 127.0.0.1:9500 --cookie my-service --reply "origin says"
//! # a POOL: park on several relays so flooding one does not take the service down
//! gyre-origin --rendezvous a:9500 --rendezvous b:9500 --rendezvous c:9500 --cookie svc --auth
//! ```
//!
//! Honest ceiling on the pool: it **dilutes** a relay-targeted flood ~linearly — to deny the
//! service an attacker must flood *all* k relays, dividing their per-target volume by k — but
//! each relay still must survive its 1/k share (still capacity, D22). Distinct per-relay
//! rendezvous IDs keep a colluding subset of relays from recognising the shared service.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use gyre_cli::{authenticate, flag, flags, obfuscator, rendezvous_id_for, Session};
use gyre_net::{read_frame_obfuscated, write_frame_obfuscated};
use gyre_shield::rendezvous::dial_admitted;

#[derive(Clone)]
struct OriginConfig {
    cookie: Vec<u8>,
    reply_prefix: String,
    obfs_name: String,
    authenticated: bool,
    forward_secret: bool,
    context: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let rzv_strs = flags(&args, "--rendezvous");
    if rzv_strs.is_empty() {
        eprintln!("gyre-origin: --rendezvous host:port is required (repeat it for a pool)");
        return ExitCode::FAILURE;
    }
    let mut relays = Vec::new();
    for s in &rzv_strs {
        match s.parse::<SocketAddr>() {
            Ok(a) => relays.push(a),
            Err(_) => {
                eprintln!("gyre-origin: bad --rendezvous address {s:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    let cookie = flag(&args, "--cookie").unwrap_or_else(|| "gyre-service".to_string());
    let reply_prefix = flag(&args, "--reply").unwrap_or_else(|| "origin answers".to_string());
    let obfs_name = flag(&args, "--obfs").unwrap_or_else(|| "identity".to_string());
    // Validate the transport name once, up front, rather than panicking later in each task.
    if let Err(e) = obfuscator(&obfs_name, cookie.as_bytes()) {
        eprintln!("gyre-origin: {e}");
        return ExitCode::FAILURE;
    }
    let authenticated = args.iter().any(|a| a == "--auth");
    let forward_secret = args.iter().any(|a| a == "--forward-secret");
    let context = flag(&args, "--context").unwrap_or_else(|| "default".to_string());

    let mode = if authenticated {
        "authenticated session".to_string()
    } else if forward_secret {
        format!("forward-secret session, context {context:?}")
    } else {
        format!("transport {obfs_name}")
    };
    println!(
        "gyre-origin: no inbound address; parked across {} relay(s) {relays:?} under cookie {cookie:?} ({mode})",
        relays.len()
    );

    let cfg = OriginConfig {
        cookie: cookie.into_bytes(),
        reply_prefix,
        obfs_name,
        authenticated,
        forward_secret,
        context,
    };

    // One supervised park-loop per relay, so the origin stays reachable via the others when any
    // one relay is flooded or down.
    let mut handles = Vec::new();
    for rzv in relays {
        handles.push(tokio::spawn(serve_relay(rzv, cfg.clone())));
    }
    // Run until killed. (Each loop is endless; this keeps the process alive.)
    for h in handles {
        let _ = h.await;
    }
    ExitCode::SUCCESS
}

/// Park on one relay forever: park, serve one request, re-park. Transient relay failures back
/// off and retry so the origin re-appears when the relay recovers.
async fn serve_relay(rzv: SocketAddr, cfg: OriginConfig) {
    let obfs = obfuscator(&cfg.obfs_name, &cfg.cookie).expect("transport validated in main");
    let match_key = if cfg.authenticated {
        rendezvous_id_for(&cfg.cookie, &rzv)
    } else {
        cfg.cookie.clone()
    };

    loop {
        let mut stream = match dial_admitted(rzv, &match_key).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("gyre-origin [{rzv}]: park failed: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        // With --auth the session is established only after the peer proves it knows the cookie;
        // a hijacker who reached us via the rendezvous ID is rejected here and we re-park.
        let mut session = if cfg.authenticated {
            match authenticate(&mut stream, &cfg.cookie, false).await {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!(
                        "gyre-origin [{rzv}]: rejected a peer that failed authentication: {e}"
                    );
                    continue;
                }
            }
        } else {
            cfg.forward_secret
                .then(|| Session::new(&cfg.cookie, &cfg.context, false))
        };

        let request = if let Some(s) = session.as_mut() {
            s.recv(&mut stream).await
        } else {
            read_frame_obfuscated(&mut stream, obfs.as_ref()).await
        };

        match request {
            Ok(Some(request)) => {
                let mut response = cfg.reply_prefix.clone().into_bytes();
                response.extend_from_slice(b": ");
                response.extend_from_slice(&request);
                let sent = if let Some(s) = session.as_mut() {
                    s.send(&mut stream, &response).await
                } else {
                    write_frame_obfuscated(&mut stream, obfs.as_ref(), &response).await
                };
                if let Err(e) = sent {
                    eprintln!("gyre-origin [{rzv}]: reply failed: {e}");
                }
                println!(
                    "  [{rzv}] served a request ({} bytes) and re-parking",
                    request.len()
                );
            }
            Ok(None) => { /* peer went away before sending; re-park */ }
            Err(e) => eprintln!("gyre-origin [{rzv}]: read error: {e}"),
        }
    }
}
