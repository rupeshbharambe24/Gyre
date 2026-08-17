//! **`gyre-reach`** — reach a `gyre-origin` through the guarded relay(s), or flood the gate.
//!
//! Reach (default): solve the admission puzzle, present the cookie, exchange a message. Give
//! several `--rendezvous` for a **pool** — the client fails over across them, so a flooded or
//! dead relay is skipped for a survivor.
//! ```text
//! gyre-reach --rendezvous 127.0.0.1:9500 --cookie my-service --message "hello"
//! gyre-reach --rendezvous a:9500 --rendezvous b:9500 --cookie svc --auth   # pool + failover
//! ```
//!
//! Flood: open N connections that DO NOT solve the puzzle, and report how many the gate refused.
//! ```text
//! gyre-reach --rendezvous 127.0.0.1:9500 --flood 50
//! ```

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use gyre_cli::{
    authenticate, flag, flag_or, flags, obfuscator, rendezvous_id_for, visiting_order, Session,
};
use gyre_net::{read_frame, read_frame_obfuscated, write_frame, write_frame_obfuscated};
use gyre_shield::rendezvous::dial_admitted;
use tokio::net::TcpStream;

struct ReachConfig {
    cookie: Vec<u8>,
    message: Vec<u8>,
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
        eprintln!("gyre-reach: --rendezvous host:port is required (repeat it for a pool)");
        return ExitCode::FAILURE;
    }
    let mut relays = Vec::new();
    for s in &rzv_strs {
        match s.parse::<SocketAddr>() {
            Ok(a) => relays.push(a),
            Err(_) => {
                eprintln!("gyre-reach: bad --rendezvous address {s:?}");
                return ExitCode::FAILURE;
            }
        }
    }

    let flood = match flag_or::<usize>(&args, "--flood", 0) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("gyre-reach: {e}");
            return ExitCode::FAILURE;
        }
    };
    if flood > 0 {
        return flood_the_gate(relays[0], flood).await;
    }

    let cookie = flag(&args, "--cookie").unwrap_or_else(|| "gyre-service".to_string());
    let message = flag(&args, "--message").unwrap_or_else(|| "ping".to_string());
    let obfs_name = flag(&args, "--obfs").unwrap_or_else(|| "identity".to_string());
    if let Err(e) = obfuscator(&obfs_name, cookie.as_bytes()) {
        eprintln!("gyre-reach: {e}");
        return ExitCode::FAILURE;
    }
    let attempt_timeout = match flag_or::<u64>(&args, "--attempt-timeout-secs", 8) {
        Ok(s) => Duration::from_secs(s),
        Err(e) => {
            eprintln!("gyre-reach: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = ReachConfig {
        cookie: cookie.into_bytes(),
        message: message.into_bytes(),
        obfs_name,
        authenticated: args.iter().any(|a| a == "--auth"),
        forward_secret: args.iter().any(|a| a == "--forward-secret"),
        context: flag(&args, "--context").unwrap_or_else(|| "default".to_string()),
    };

    // Try relays in a randomized order, taking the first that answers. Flooding or killing one
    // relay just costs a per-attempt timeout before a survivor is used.
    for idx in visiting_order(relays.len()) {
        let rzv = relays[idx];
        match tokio::time::timeout(attempt_timeout, try_reach_once(rzv, &cfg)).await {
            Ok(Ok(reply)) => {
                println!(
                    "gyre-reach: ADMITTED via {rzv} -> reply {:?}",
                    String::from_utf8_lossy(&reply)
                );
                return ExitCode::SUCCESS;
            }
            Ok(Err(e)) => eprintln!("gyre-reach: relay {rzv} failed: {e}; trying next"),
            Err(_) => eprintln!("gyre-reach: relay {rzv} timed out; trying next"),
        }
    }
    eprintln!("gyre-reach: all {} relay(s) failed", relays.len());
    ExitCode::FAILURE
}

/// One attempt against one relay: dial, run the selected mode, return the origin's reply.
async fn try_reach_once(rzv: SocketAddr, cfg: &ReachConfig) -> Result<Vec<u8>, String> {
    let match_key = if cfg.authenticated {
        rendezvous_id_for(&cfg.cookie, &rzv)
    } else {
        cfg.cookie.clone()
    };
    let mut stream = dial_admitted(rzv, &match_key)
        .await
        .map_err(|e| format!("admission failed: {e}"))?;

    if cfg.authenticated {
        let mut session = authenticate(&mut stream, &cfg.cookie, true)
            .await
            .map_err(|e| format!("authentication failed: {e}"))?;
        session
            .send(&mut stream, &cfg.message)
            .await
            .map_err(|e| format!("send failed: {e}"))?;
        return recv_reply_session(&mut session, &mut stream).await;
    }

    if cfg.forward_secret {
        let mut session = Session::new(&cfg.cookie, &cfg.context, true);
        session
            .send(&mut stream, &cfg.message)
            .await
            .map_err(|e| format!("send failed: {e}"))?;
        return recv_reply_session(&mut session, &mut stream).await;
    }

    let obfs = obfuscator(&cfg.obfs_name, &cfg.cookie).expect("transport validated in main");
    write_frame_obfuscated(&mut stream, obfs.as_ref(), &cfg.message)
        .await
        .map_err(|e| format!("send failed: {e}"))?;
    match read_frame_obfuscated(&mut stream, obfs.as_ref()).await {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => Err("origin closed without replying".to_string()),
        Err(e) => Err(format!("read failed: {e}")),
    }
}

async fn recv_reply_session(
    session: &mut Session,
    stream: &mut TcpStream,
) -> Result<Vec<u8>, String> {
    match session.recv(stream).await {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => Err("origin closed without replying".to_string()),
        Err(e) => Err(format!("read failed: {e}")),
    }
}

/// Open `n` connections that skip the proof-of-work, and count how many the gate refuses.
async fn flood_the_gate(rzv: SocketAddr, n: usize) -> ExitCode {
    let mut refused = 0usize;
    let mut served = 0usize;
    for _ in 0..n {
        let Ok(mut attacker) = TcpStream::connect(rzv).await else {
            continue;
        };
        let _ = write_frame(&mut attacker, b"no-proof-of-work").await;
        let _ = read_frame(&mut attacker).await; // the server's challenge, ignored
        match tokio::time::timeout(Duration::from_secs(2), read_frame(&mut attacker)).await {
            Ok(Ok(None)) | Ok(Err(_)) => refused += 1,
            _ => served += 1,
        }
    }
    println!("gyre-reach flood: {n} connections with no proof-of-work -> {refused} refused, {served} served");
    if served == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
