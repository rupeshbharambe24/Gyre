//! **`gyre-dir`** — a 2-server IT-PIR directory server.
//!
//! Holds `--records N` deterministic demo records and answers private-information-retrieval
//! queries over a socket: given a query mask, it replies with the XOR of the selected records
//! and learns nothing about which record the client actually wanted. Run **two** of these
//! (on different hosts, under different operators) so the non-collusion assumption is real.
//!
//! ```text
//! gyre-dir --listen 127.0.0.1:9701 --records 64
//! gyre-dir --listen 127.0.0.1:9702 --records 64      # a second, independent operator
//! ```
//!
//! Records here are deterministic (`gyre_cli::demo_record`) so two instances agree with no
//! distribution step — simulation-only, exactly like the testnet relay keys. A real
//! deployment replicates the *signed consensus* records.

use std::process::ExitCode;
use std::sync::Arc;

use gyre_cli::{demo_record, flag, flag_or, serve_pir};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let listen = flag(&args, "--listen").unwrap_or_else(|| "0.0.0.0:9701".to_string());
    let records = match flag_or::<usize>(&args, "--records", 64) {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            eprintln!("gyre-dir: --records must be > 0");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("gyre-dir: {e}");
            return ExitCode::FAILURE;
        }
    };

    let dir = Arc::new(gyre_pir::Directory::new(
        (0..records).map(demo_record).collect(),
    ));

    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gyre-dir: cannot bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(listen);
    println!("gyre-dir: PIR directory server on {bound} ({records} records)");
    println!("  answers query masks with an XOR; a single server never learns the target index");

    if let Err(e) = serve_pir(listener, dir).await {
        eprintln!("gyre-dir: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
