//! S4 test: the FAST and MIX lanes both deliver correctly — the lane changes the
//! delay policy, not correctness.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use whirl_common::FlowClass;
use whirl_net::{read_frame, send_onion, Directory, RelayServer};
use whirl_sphinx::{Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

#[tokio::test]
async fn both_lanes_deliver_the_payload() {
    let relays: Vec<Relay> = (1u8..=2).map(|i| Relay::new([i; ADDRESS_LEN])).collect();

    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        entries.push((relay.address(), listener.local_addr().unwrap()));
        listeners.push(listener);
    }
    let dest = [50u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut conn, _) = sink.accept().await.unwrap();
            let frame = read_frame(&mut conn).await.unwrap().unwrap();
            tx.send(frame).await.unwrap();
        }
    });

    let fast_msg = b"fast lane payload".to_vec();
    let mix_msg = b"mix lane payload".to_vec();
    send_onion(
        first_hop,
        &route,
        dest,
        &fast_msg,
        FlowClass::Fast.default_mean_hop_delay(),
    )
    .await
    .unwrap();
    send_onion(
        first_hop,
        &route,
        dest,
        &mix_msg,
        FlowClass::Mix.default_mean_hop_delay(),
    )
    .await
    .unwrap();

    let mut got = HashSet::new();
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery timed out")
            .unwrap();
        got.insert(frame);
    }
    assert!(got.contains(&fast_msg), "FAST lane message must arrive");
    assert!(got.contains(&mix_msg), "MIX lane message must arrive");
}
