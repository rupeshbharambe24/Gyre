//! **S1 demo.** Spins up a small localhost testnet of relays, then wraps a message
//! into a Sphinx onion at the "client" and sends it in — watching it cross real
//! sockets, hop by hop, until the destination receives the exact payload.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p whirl-node
//! ```
//!
//! Each relay only ever learns the *next* hop; the relay lines (on stderr) show the
//! forwarding, and the client/destination lines (on stdout) show the round trip.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use whirl_common::{FlowClass, DEFAULT_HOPS};
use whirl_net::{read_frame, send_to, Directory, RelayServer};
use whirl_sphinx::{null_surb, packet_to_bytes, wrap, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

#[tokio::main]
async fn main() {
    println!(
        "Whirlpool · S1 — Sphinx onion over the network  ({} hops, lane={})",
        DEFAULT_HOPS,
        FlowClass::Fast
    );
    println!("{}", "-".repeat(64));

    // A localhost circuit of DEFAULT_HOPS relays, address-labelled 1..=N.
    let relays: Vec<Relay> = (1..=DEFAULT_HOPS as u8)
        .map(|i| Relay::new([i; ADDRESS_LEN]))
        .collect();

    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let addr = listener.local_addr().unwrap();
        println!("relay #{:<2} listening on {addr}", relay.address()[0]);
        entries.push((relay.address(), addr));
        listeners.push(listener);
    }

    // The destination sink.
    let dest_label = [42u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let sink_addr = sink.local_addr().unwrap();
    println!("dest  #{:<2} listening on {sink_addr}", dest_label[0]);
    entries.push((dest_label, sink_addr));

    let first_hop = entries[0].1;
    let dir = Directory::from_entries(entries);
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();

    // Start every relay (verbose, so the demo prints each forward).
    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone()).verbose(true);
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // The destination waits for one delivered frame.
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut conn, _) = sink.accept().await.unwrap();
        let delivered = read_frame(&mut conn).await.unwrap().unwrap();
        let _ = tx.send(delivered);
    });

    let message = b"hello from the client, across the whirlpool network";
    println!("{}", "-".repeat(64));
    println!(
        "client  wrap {} bytes -> send to first hop {first_hop}",
        message.len()
    );
    let packet = wrap(message, &route, dest_label, null_surb()).expect("wrap onion");
    send_to(first_hop, &packet_to_bytes(&packet))
        .await
        .expect("send to first hop");

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("delivery timed out")
        .expect("sink dropped the sender");

    println!("{}", "-".repeat(64));
    assert_eq!(delivered, message, "payload survived the network intact");
    println!("delivered: {:?}", String::from_utf8_lossy(&delivered));
    println!("OK  onion crossed {DEFAULT_HOPS} networked hops; no relay saw both ends.");
}
