//! A standalone Gyre relay: one process, one socket, real onions.
//!
//! ```text
//! gyre-relay --label r1 --listen 0.0.0.0:9001 \
//!            --relay r1=10.0.0.1:9001 --relay r2=10.0.0.2:9001 --relay r3=10.0.0.3:9001
//! ```
//!
//! Every relay is given the same `--relay` list so it can resolve the next hop an onion
//! names. It peels exactly one layer, honours the mixing delay sealed inside for it, and
//! forwards — learning only its immediate neighbour, never both ends.

use std::process::ExitCode;

use gyre_cli::{flag, label_to_address, parse_relays, testnet_relay};
use gyre_net::{Directory, RelayServer};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let Some(label) = flag(&args, "--label") else {
        eprintln!("gyre-relay: --label is required (e.g. --label r1)");
        return ExitCode::FAILURE;
    };
    let listen = flag(&args, "--listen").unwrap_or_else(|| "0.0.0.0:9001".to_string());
    let peers = match parse_relays(&args) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            eprintln!("gyre-relay: at least one --relay label=host:port is required");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("gyre-relay: {e}");
            return ExitCode::FAILURE;
        }
    };

    let directory = Directory::from_entries(
        peers
            .iter()
            .map(|p| (label_to_address(&p.label), p.addr))
            .collect::<Vec<_>>(),
    );

    let relay = testnet_relay(&label);
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gyre-relay {label}: cannot bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "gyre-relay {label} listening on {} ({} peers known)",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or(listen),
        peers.len()
    );

    // Serves until killed; the simulator or supervisor decides when that is.
    if let Err(e) = RelayServer::new(relay, directory)
        .verbose(true)
        .serve(listener)
        .await
    {
        eprintln!("gyre-relay {label}: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
