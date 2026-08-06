//! A standalone Gyre client: builds real onions and sends them through real relays.
//!
//! ```text
//! gyre-client --route r1,r2,r3 --dest 10.0.0.9:9100 --lane mix --packets 8 \
//!             --relay r1=10.0.0.1:9001 --relay r2=10.0.0.2:9001 --relay r3=10.0.0.3:9001
//! ```
//!
//! Prints one line per packet and a summary, so a simulation run produces parseable
//! output rather than just a exit code.

use std::process::ExitCode;
use std::time::Instant;

use gyre_cli::{flag, label_to_address, parse_relays, testnet_relay};
use gyre_common::FlowClass;
use gyre_net::send_onion;
use gyre_sphinx::DEST_ADDRESS_LEN;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let peers = match parse_relays(&args) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            eprintln!("gyre-client: at least one --relay label=host:port is required");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("gyre-client: {e}");
            return ExitCode::FAILURE;
        }
    };

    let route_labels: Vec<String> = flag(&args, "--route")
        .unwrap_or_else(|| {
            peers
                .iter()
                .map(|p| p.label.clone())
                .collect::<Vec<_>>()
                .join(",")
        })
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let lane = match flag(&args, "--lane").as_deref() {
        Some("fast") | None => FlowClass::Fast,
        Some("mix") => FlowClass::Mix,
        Some(other) => {
            eprintln!("gyre-client: --lane must be fast or mix, got {other:?}");
            return ExitCode::FAILURE;
        }
    };
    let packets: usize = flag(&args, "--packets")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    // Resolve the route to entry address + relay nodes.
    let relays: Vec<_> = route_labels.iter().map(|l| testnet_relay(l)).collect();
    let route: Vec<_> = relays.iter().map(|r| r.as_node()).collect();
    let Some(entry) = peers.iter().find(|p| p.label == route_labels[0]) else {
        eprintln!(
            "gyre-client: route starts at {:?}, which is not in --relay",
            route_labels[0]
        );
        return ExitCode::FAILURE;
    };

    let mut dest = [0u8; DEST_ADDRESS_LEN];
    let dest_label = flag(&args, "--dest").unwrap_or_else(|| "destination".to_string());
    let digest = label_to_address(&dest_label);
    dest.copy_from_slice(&digest[..DEST_ADDRESS_LEN.min(digest.len())]);

    println!(
        "gyre-client: route {} via {} · lane {} · {packets} packet(s)",
        route_labels.join(" -> "),
        entry.addr,
        lane.as_str()
    );

    let started = Instant::now();
    let mut sent = 0usize;
    for i in 0..packets {
        let payload = format!("gyre packet {i}").into_bytes();
        let t0 = Instant::now();
        match send_onion(
            entry.addr,
            &route,
            dest,
            &payload,
            lane.default_mean_hop_delay(),
        )
        .await
        {
            Ok(()) => {
                sent += 1;
                println!("  packet {i}: accepted by entry in {:?}", t0.elapsed());
            }
            Err(e) => eprintln!("  packet {i}: FAILED: {e}"),
        }
    }

    println!(
        "gyre-client: {sent}/{packets} packets handed to the fabric in {:?}",
        started.elapsed()
    );
    if sent == packets {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
