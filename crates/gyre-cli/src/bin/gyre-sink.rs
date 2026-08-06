//! A destination for a Gyre testnet: accepts what the exit relay delivers and prints it.
//!
//! ```text
//! gyre-sink --listen 0.0.0.0:9100
//! ```
//!
//! Without this the exit has nowhere to deliver to, and a run cannot show end-to-end
//! success — only that packets were accepted. Delivery is the measurement that matters.

use std::process::ExitCode;
use std::time::Instant;

use gyre_cli::flag;
use gyre_net::read_frame;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let listen = flag(&args, "--listen").unwrap_or_else(|| "0.0.0.0:9100".to_string());
    let expect: usize = flag(&args, "--expect")
        .and_then(|v| v.parse().ok())
        .unwrap_or(usize::MAX);

    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gyre-sink: cannot bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("gyre-sink listening on {listen}");

    let started = Instant::now();
    let mut received = 0usize;
    while received < expect {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        while let Ok(Some(frame)) = read_frame(&mut stream).await {
            received += 1;
            println!(
                "  delivered #{received} after {:?}: {:?}",
                started.elapsed(),
                String::from_utf8_lossy(&frame)
            );
            if received >= expect {
                break;
            }
        }
    }
    println!("gyre-sink: {received} payload(s) delivered end to end");
    ExitCode::SUCCESS
}
