//! **`gyre-reach`** — reach a `gyre-origin` through the guarded relay, or flood the gate to
//! see it refuse.
//!
//! Two modes, both talking to a real `gyre-rendezvous` daemon over real sockets:
//!
//! Reach (default): solve the admission puzzle, present the cookie, exchange a message.
//! ```text
//! gyre-reach --rendezvous 127.0.0.1:9500 --cookie my-service --message "hello"
//! ```
//!
//! Flood: open N connections that DO NOT solve the puzzle, and report how many the gate
//! refused. This is the L7 admission defence, demonstrated across OS processes.
//! ```text
//! gyre-reach --rendezvous 127.0.0.1:9500 --flood 50
//! ```

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use gyre_cli::{flag, flag_or};
use gyre_net::{read_frame, write_frame};
use gyre_shield::rendezvous::dial_admitted;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let Some(rzv) = flag(&args, "--rendezvous") else {
        eprintln!("gyre-reach: --rendezvous host:port is required");
        return ExitCode::FAILURE;
    };
    let Ok(rzv): Result<SocketAddr, _> = rzv.parse() else {
        eprintln!("gyre-reach: bad --rendezvous address {rzv:?}");
        return ExitCode::FAILURE;
    };

    let flood = match flag_or::<usize>(&args, "--flood", 0) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("gyre-reach: {e}");
            return ExitCode::FAILURE;
        }
    };

    if flood > 0 {
        return flood_the_gate(rzv, flood).await;
    }

    let cookie = flag(&args, "--cookie").unwrap_or_else(|| "gyre-service".to_string());
    let message = flag(&args, "--message").unwrap_or_else(|| "ping".to_string());

    // Solve the puzzle and reach the origin.
    let mut stream = match dial_admitted(rzv, cookie.as_bytes()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gyre-reach: admission failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_frame(&mut stream, message.as_bytes()).await {
        eprintln!("gyre-reach: send failed: {e}");
        return ExitCode::FAILURE;
    }
    match read_frame(&mut stream).await {
        Ok(Some(reply)) => {
            println!(
                "gyre-reach: ADMITTED (solved the puzzle) -> reply {:?}",
                String::from_utf8_lossy(&reply)
            );
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("gyre-reach: origin closed without replying");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("gyre-reach: read failed: {e}");
            ExitCode::FAILURE
        }
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
        // A real attacker ignores the admission protocol entirely.
        let _ = write_frame(&mut attacker, b"no-proof-of-work").await;
        let _ = read_frame(&mut attacker).await; // the server's challenge, ignored
        match tokio::time::timeout(Duration::from_secs(2), read_frame(&mut attacker)).await {
            Ok(Ok(None)) | Ok(Err(_)) => refused += 1, // connection closed = refused
            _ => served += 1,                          // still open = wrongly served
        }
    }
    println!("gyre-reach flood: {n} connections with no proof-of-work -> {refused} refused, {served} served");
    if served == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
