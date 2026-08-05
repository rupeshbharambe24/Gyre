//! **S2 demo.** Routes a real onion across a localhost testnet while a stream of
//! Loopix cover "loops" runs alongside it, and each relay holds every packet for an
//! exponential (Poisson) delay before forwarding. On the wire, cover and real look
//! identical; the delays reorder traffic so timing can't line packets up.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p whirl-node
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use whirl_common::{FlowClass, DEFAULT_HOPS};
use whirl_net::{emit_loops, read_frame, send_to, Directory, RelayServer};
use whirl_sphinx::{
    exponential_delays, null_surb, packet_to_bytes, wrap_with_delays, Relay, ADDRESS_LEN,
    DEST_ADDRESS_LEN,
};

#[tokio::main]
async fn main() {
    println!(
        "Whirlpool · S2 — Poisson mixing + cover traffic  ({} hops, lane={})",
        DEFAULT_HOPS,
        FlowClass::Mix
    );
    println!("{}", "-".repeat(64));

    let relays: Vec<Relay> = (1..=DEFAULT_HOPS as u8)
        .map(|i| Relay::new([i; ADDRESS_LEN]))
        .collect();

    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let addr = listener.local_addr().unwrap();
        println!("relay #{:<2} on {addr}", relay.address()[0]);
        entries.push((relay.address(), addr));
        listeners.push(listener);
    }

    // Real destination (#42) and a loop sink (#77) for the cover traffic.
    let dest_label = [42u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.expect("bind dest");
    entries.push((dest_label, sink.local_addr().unwrap()));
    let loop_label = [77u8; DEST_ADDRESS_LEN];
    let loop_sink = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loop sink");
    entries.push((loop_label, loop_sink.local_addr().unwrap()));

    let first_hop = entries[0].1;
    let dir = Directory::from_entries(entries);
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();

    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone()).verbose(true);
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // Real destination: wait for one delivered frame.
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut conn, _) = sink.accept().await.unwrap();
        let delivered = read_frame(&mut conn).await.unwrap().unwrap();
        let _ = tx.send(delivered);
    });
    // Loop sink: silently drain cover packets.
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = loop_sink.accept().await {
            tokio::spawn(async move {
                let _ = read_frame(&mut conn).await;
            });
        }
    });

    // Cover traffic: a few Loopix loops, indistinguishable from real on the wire.
    let cover_route = route.clone();
    tokio::spawn(async move {
        let _ = emit_loops(
            first_hop,
            &cover_route,
            loop_label,
            Duration::from_millis(15),
            Duration::from_millis(10),
            3,
        )
        .await;
    });

    // The real message, with exponential per-hop mixing delays.
    let message = b"a real message, mixed among the cover traffic";
    println!("{}", "-".repeat(64));
    println!(
        "client  send real packet ({} bytes) with Poisson per-hop delay; cover loops running",
        message.len()
    );
    let delays = exponential_delays(route.len(), Duration::from_millis(40));
    let packet = wrap_with_delays(message, &route, dest_label, null_surb(), &delays).expect("wrap");
    send_to(first_hop, &packet_to_bytes(&packet))
        .await
        .expect("send");

    let delivered = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("delivery timed out")
        .expect("sink dropped the sender");

    println!("{}", "-".repeat(64));
    assert_eq!(delivered, message, "payload survived mixing + cover intact");
    println!("delivered: {:?}", String::from_utf8_lossy(&delivered));
    println!("OK  real packet mixed among cover, held by Poisson delays, delivered intact.");
}
