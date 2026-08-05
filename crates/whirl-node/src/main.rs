//! **S3 demo.** Erasure-codes a message into fragments, sends each along its own
//! disjoint path (with Poisson per-hop mixing delay), deliberately *drops one whole
//! path*, and the destination still reassembles the message from the fragments that
//! arrive — the whirlpool "branches", done honestly.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p whirl-node
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use whirl_common::{FlowClass, DEFAULT_HOPS};
use whirl_fec::{encode, Fragment, Reassembler};
use whirl_net::{read_frame, send_onion, Directory, RelayServer};
use whirl_sphinx::{Node, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

const DATA: usize = 2; // data shards
const PARITY: usize = 1; // parity shards -> 3 fragments, any 2 reconstruct
const PATHS: usize = DATA + PARITY;

#[tokio::main]
async fn main() {
    println!(
        "Whirlpool · S3 — erasure-coded multipath  ({DATA}-of-{PATHS} across disjoint paths, lane={})",
        FlowClass::Mix
    );
    println!("{}", "-".repeat(68));

    // PATHS disjoint routes, each DEFAULT_HOPS hops -> PATHS * DEFAULT_HOPS relays.
    let relay_count = (PATHS * DEFAULT_HOPS) as u8;
    let relays: Vec<Relay> = (1..=relay_count)
        .map(|i| Relay::new([i; ADDRESS_LEN]))
        .collect();

    let mut listeners = Vec::new();
    let mut addrs = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let addr = listener.local_addr().unwrap();
        addrs.push(addr);
        entries.push((relay.address(), addr));
        listeners.push(listener);
    }
    let dest = [200u8; DEST_ADDRESS_LEN];
    let sink = TcpListener::bind("127.0.0.1:0").await.expect("bind dest");
    entries.push((dest, sink.local_addr().unwrap()));
    let dir = Directory::from_entries(entries);

    // Build the disjoint paths (each a run of DEFAULT_HOPS distinct relays).
    let paths: Vec<(SocketAddr, Vec<Node>)> = (0..PATHS)
        .map(|p| {
            let base = p * DEFAULT_HOPS;
            let route: Vec<Node> = (0..DEFAULT_HOPS)
                .map(|h| relays[base + h].as_node())
                .collect();
            (addrs[base], route)
        })
        .collect();
    for (p, path) in paths.iter().enumerate() {
        let labels: Vec<u8> = path
            .1
            .iter()
            .enumerate()
            .map(|(h, _)| (p * DEFAULT_HOPS + h + 1) as u8)
            .collect();
        println!("path {p}: relays {labels:?} -> dest #{}", dest[0]);
    }

    for (relay, listener) in relays.into_iter().zip(listeners) {
        let server = RelayServer::new(relay, dir.clone()).verbose(true);
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
    }

    // Destination collects DATA fragment frames (that is all it needs).
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PATHS);
    tokio::spawn(async move {
        for _ in 0..DATA {
            let (mut conn, _) = sink.accept().await.unwrap();
            let frame = read_frame(&mut conn).await.unwrap().unwrap();
            tx.send(frame).await.unwrap();
        }
    });

    // Encode and send every fragment EXCEPT one — dropping a whole path.
    let message = b"a message split across branches, rebuilt from a subset";
    let frags = encode(message, 0x51C0, DATA, PARITY).expect("encode");
    let dropped = 1usize;
    println!("{}", "-".repeat(68));
    println!(
        "client  split {} bytes into {PATHS} fragments; sending all but path {dropped} (dropped)",
        message.len()
    );
    for (i, (first_hop, route)) in paths.iter().enumerate() {
        if i == dropped {
            continue;
        }
        send_onion(
            *first_hop,
            route,
            dest,
            &frags[i].to_bytes(),
            Duration::from_millis(30),
        )
        .await
        .expect("send fragment");
    }

    // Reassemble from whatever arrives.
    let mut reasm = Reassembler::new();
    let mut recovered = None;
    for _ in 0..DATA {
        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("fragment timed out")
            .unwrap();
        let frag = Fragment::from_bytes(&frame).unwrap();
        if let Some(m) = reasm.insert(frag).expect("reassemble") {
            recovered = Some(m);
        }
    }

    println!("{}", "-".repeat(68));
    let recovered = recovered.expect("message reassembled");
    assert_eq!(recovered, message, "reassembled message must match");
    println!("delivered: {:?}", String::from_utf8_lossy(&recovered));
    println!(
        "OK  path {dropped} was dropped, yet {DATA}-of-{PATHS} fragments rebuilt the message."
    );
}
