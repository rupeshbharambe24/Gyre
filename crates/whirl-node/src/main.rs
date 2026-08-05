//! **S4 demo.** The same fabric, two lanes: a FAST flow (onion-only, ~zero added
//! delay) and a MIX flow (Poisson per-hop delay). Same route, same message — the
//! client picks the tradeoff per flow, and the elapsed times show its honest cost.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p whirl-node
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use whirl_common::{FlowClass, DEFAULT_HOPS};
use whirl_net::{read_frame, send_onion, Directory, RelayServer};
use whirl_sphinx::{Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

#[tokio::main]
async fn main() {
    println!("Whirlpool · S4 — FAST / MIX adaptive lanes  ({DEFAULT_HOPS} hops)");
    println!("{}", "-".repeat(64));

    let relays: Vec<Relay> = (1..=DEFAULT_HOPS as u8)
        .map(|i| Relay::new([i; ADDRESS_LEN]))
        .collect();

    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        entries.push((relay.address(), listener.local_addr().unwrap()));
        listeners.push(listener);
    }
    let dest = [42u8; DEST_ADDRESS_LEN];
    let sink = Arc::new(TcpListener::bind("127.0.0.1:0").await.expect("bind dest"));
    entries.push((dest, sink.local_addr().unwrap()));

    let first_hop = entries[0].1;
    let dir = Directory::from_entries(entries);
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();

    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone());
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // Run each lane sequentially and time the round trip through the fabric.
    for class in [FlowClass::Fast, FlowClass::Mix] {
        let (tx, rx) = oneshot::channel();
        let sink = sink.clone();
        tokio::spawn(async move {
            let (mut conn, _) = sink.accept().await.unwrap();
            let frame = read_frame(&mut conn).await.unwrap().unwrap();
            let _ = tx.send(frame);
        });

        let message = format!("{class} lane message");
        let start = Instant::now();
        send_onion(
            first_hop,
            &route,
            dest,
            message.as_bytes(),
            class.default_mean_hop_delay(),
        )
        .await
        .expect("send");
        let delivered = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("delivery timed out")
            .expect("sink dropped the sender");
        let elapsed = start.elapsed();

        assert_eq!(delivered, message.as_bytes(), "payload delivered intact");
        println!(
            "{:>4} lane   mean/hop {:>3}ms   ->   delivered in {:>4}ms",
            class.as_str().to_uppercase(),
            class.default_mean_hop_delay().as_millis(),
            elapsed.as_millis()
        );
    }

    println!("{}", "-".repeat(64));
    println!("OK  same route, two lanes: FAST trades anonymity for latency, MIX the reverse.");
}
