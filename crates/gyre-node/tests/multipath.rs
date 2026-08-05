//! S3 test: a message is erasure-coded into fragments sent over disjoint paths, and
//! the destination reassembles it even when a whole path is dropped.

use std::net::SocketAddr;
use std::time::Duration;

use gyre_fec::{encode, Fragment, Reassembler};
use gyre_net::{read_frame, send_onion, Directory, RelayServer};
use gyre_sphinx::{Node, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test]
async fn multipath_reassembles_after_one_path_is_dropped() {
    // Three disjoint 2-hop paths => six relays (path p = relays[2p], relays[2p+1]).
    let relays: Vec<Relay> = (1u8..=6).map(|i| Relay::new([i; ADDRESS_LEN])).collect();

    let mut listeners = Vec::new();
    let mut addrs = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        addrs.push(addr);
        entries.push((relay.address(), addr));
        listeners.push(listener);
    }
    let dest = [200u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    entries.push((dest, sink.local_addr().unwrap()));
    let dir = Directory::from_entries(entries);

    // Build the three (first_hop, 2-node route) paths before moving relays.
    let paths: Vec<(SocketAddr, Vec<Node>)> = (0..3)
        .map(|p| {
            (
                addrs[2 * p],
                vec![relays[2 * p].as_node(), relays[2 * p + 1].as_node()],
            )
        })
        .collect();

    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone());
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // The destination collects two delivered fragment frames.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut conn, _) = sink.accept().await.unwrap();
            let frame = read_frame(&mut conn).await.unwrap().unwrap();
            tx.send(frame).await.unwrap();
        }
    });

    // Encode into 3 fragments (data=2, parity=1: any 2 reconstruct).
    let message = b"multipath: reassemble me from any two of three fragments".to_vec();
    let frags = encode(&message, 0x1234, 2, 1).unwrap();
    assert_eq!(frags.len(), 3);

    // Send fragment 0 via path 0 and fragment 2 via path 2 — path 1 is dropped.
    for i in [0usize, 2] {
        let (first_hop, route) = &paths[i];
        send_onion(
            *first_hop,
            route,
            dest,
            &frags[i].to_bytes(),
            Duration::ZERO,
        )
        .await
        .unwrap();
    }

    // Reassemble from the two fragments that arrive.
    let mut reasm = Reassembler::new();
    let mut recovered = None;
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("fragment delivery timed out")
            .unwrap();
        let frag = Fragment::from_bytes(&frame).unwrap();
        if let Some(m) = reasm.insert(frag).unwrap() {
            recovered = Some(m);
        }
    }
    assert_eq!(
        recovered.unwrap(),
        message,
        "reassembled from 2 of 3 paths; the dropped path cost nothing"
    );
}
