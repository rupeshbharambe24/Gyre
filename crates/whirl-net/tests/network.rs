//! End-to-end S1 test: an onion really crosses three networked relays.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use whirl_net::{read_frame, send_to, Directory, RelayServer};
use whirl_sphinx::{null_surb, packet_to_bytes, wrap, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

#[tokio::test]
async fn onion_routes_through_three_networked_relays() {
    // Three relays, address-labelled 1, 2, 3.
    let relays: Vec<Relay> = (1u8..=3).map(|i| Relay::new([i; ADDRESS_LEN])).collect();

    // Bind a listener for each relay on an ephemeral localhost port.
    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        entries.push((relay.address(), listener.local_addr().unwrap()));
        listeners.push(listener);
    }

    // A destination "sink" labelled 9.
    let dest_label = [9u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    entries.push((dest_label, sink.local_addr().unwrap()));

    let first_hop = entries[0].1;
    let dir = Directory::from_entries(entries);

    // The client builds the route (each relay's descriptor) before we move the
    // relays into their servers.
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();

    // Start every relay server.
    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone());
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // The destination waits for exactly one delivered frame.
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut conn, _) = sink.accept().await.unwrap();
        let delivered = read_frame(&mut conn).await.unwrap().unwrap();
        let _ = tx.send(delivered);
    });

    // Client wraps a message and sends it to the first hop.
    let message = b"whirlpool S1: an onion over the wire".to_vec();
    let packet = wrap(&message, &route, dest_label, null_surb()).unwrap();
    send_to(first_hop, &packet_to_bytes(&packet)).await.unwrap();

    // The exact payload must arrive at the destination, having crossed the network.
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("delivery timed out")
        .expect("sink task dropped the sender");
    assert_eq!(
        delivered, message,
        "destination received the exact payload after 3 networked hops"
    );
}
