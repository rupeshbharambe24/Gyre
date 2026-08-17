//! **`gyre-rendezvous`** — the guarded rendezvous relay, as a real deployable daemon.
//!
//! This is the productionised inbound shield: a long-running process that runs
//! [`RendezvousRelay::guarded`] on a real socket, so the DoS admission gate runs in the
//! field rather than only inside the `gyre-shield` demo. Origins dial *out* to it and park
//! behind a cookie; clients dial in with the same cookie; every connection must first solve a
//! server-issued, expiring, single-use, load-scaled proof-of-work before it can park or
//! splice, and the relay bounds parked count, in-flight handshake count, handshake duration,
//! and cookie length.
//!
//! ```text
//! gyre-rendezvous --listen 0.0.0.0:9500 \
//!                 --capacity 1024 --max-inflight 256 \
//!                 --ttl-secs 30 --handshake-timeout-secs 10 --max-cookie-len 128 \
//!                 --stats-secs 5
//! ```
//!
//! **Honest ceilings (see `docs/DOS.md`):** this is L7 admission pricing plus origin-hiding.
//! It does nothing against a volumetric L3/L4 flood (put a scrubber in front — decision D22),
//! the cookie is an unauthenticated bearer secret, and the puzzle is SHA-256 (a memory-hard
//! migration is on the roadmap). What it *does* do is refuse an application-layer connection
//! flood while admitting clients that pay the work — deployable today.

use std::process::ExitCode;
use std::time::Duration;

use gyre_cli::{flag, flag_or};
use gyre_shield::rendezvous::{RelayConfig, RendezvousRelay};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let listen = flag(&args, "--listen").unwrap_or_else(|| "0.0.0.0:9500".to_string());

    // Every numeric flag fails loudly if present-but-unparseable, rather than silently
    // serving at a default the operator did not choose.
    let config = match build_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gyre-rendezvous: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stats_secs = match flag_or::<u64>(&args, "--stats-secs", 0) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gyre-rendezvous: {e}");
            return ExitCode::FAILURE;
        }
    };

    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gyre-rendezvous: cannot bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(listen);
    println!("gyre-rendezvous guarded relay listening on {bound}");
    println!(
        "  admission gate: PoW per connection · capacity {} · max-inflight {} · \
         handshake-timeout {:?} · challenge-ttl {:?} · max-cookie {} B",
        config.capacity,
        config.max_inflight,
        config.handshake_timeout,
        config.ttl,
        config.max_cookie_len
    );
    println!("  ceilings: no volumetric L3/L4 defence (put a scrubber in front, D22); cookie is a bearer secret");

    let relay = RendezvousRelay::guarded(config);

    // Optional operator heartbeat: report how many connections are currently parked, so a
    // deployment can watch the capacity bound hold under load without attaching a debugger.
    if stats_secs > 0 {
        let observer = relay.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(stats_secs));
            loop {
                ticker.tick().await;
                println!("[stats] parked {} / {}", observer.parked(), config.capacity);
            }
        });
    }

    // Serves until killed; a supervisor (systemd, the demo script, Shadow) decides when.
    if let Err(e) = relay.serve(listener).await {
        eprintln!("gyre-rendezvous: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Assemble the relay config from flags, defaulting to [`RelayConfig::default`]'s bounds.
fn build_config(args: &[String]) -> Result<RelayConfig, String> {
    let d = RelayConfig::default();
    Ok(RelayConfig {
        capacity: flag_or(args, "--capacity", d.capacity)?,
        max_inflight: flag_or(args, "--max-inflight", d.max_inflight)?,
        max_cookie_len: flag_or(args, "--max-cookie-len", d.max_cookie_len)?,
        ttl: Duration::from_secs(flag_or(args, "--ttl-secs", d.ttl.as_secs())?),
        handshake_timeout: Duration::from_secs(flag_or(
            args,
            "--handshake-timeout-secs",
            d.handshake_timeout.as_secs(),
        )?),
        parked_ttl: Duration::from_secs(flag_or(
            args,
            "--parked-ttl-secs",
            d.parked_ttl.as_secs(),
        )?),
    })
}
