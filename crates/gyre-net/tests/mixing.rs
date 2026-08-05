//! S2 test: a mix relay honours its per-hop delay, so a later packet can overtake
//! an earlier one — the observable signature of mixing.

use std::net::SocketAddr;
use std::time::Duration;

use gyre_net::{read_frame, send_to, Directory, RelayServer};
use gyre_sphinx::{
    null_surb, packet_to_bytes, wrap_with_delays, Delay, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test]
async fn a_delayed_packet_is_overtaken_by_a_later_one() {
    // Two relays: hop 1 applies the per-hop delay, hop 2 is the exit.
    let relays: Vec<Relay> = (1u8..=2).map(|i| Relay::new([i; ADDRESS_LEN])).collect();

    let mut listeners = Vec::new();
    let mut entries: Vec<([u8; ADDRESS_LEN], SocketAddr)> = Vec::new();
    for relay in &relays {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        entries.push((relay.address(), listener.local_addr().unwrap()));
        listeners.push(listener);
    }
    let dest = [9u8; DEST_ADDRESS_LEN];
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

    // The sink records delivered payloads in arrival order.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut conn, _) = sink.accept().await.unwrap();
            let frame = read_frame(&mut conn).await.unwrap().unwrap();
            tx.send(frame).await.unwrap();
        }
    });

    // Packet A holds 200ms at the first hop; packet B has no delay.
    let slow = [Delay::new_from_millis(200), Delay::new_from_nanos(0)];
    let fast = [Delay::new_from_nanos(0), Delay::new_from_nanos(0)];
    let a = wrap_with_delays(b"AAAA", &route, dest, null_surb(), &slow).unwrap();
    let b = wrap_with_delays(b"BBBB", &route, dest, null_surb(), &fast).unwrap();

    // Send A first, then B — but B should arrive first.
    send_to(first_hop, &packet_to_bytes(&a)).await.unwrap();
    send_to(first_hop, &packet_to_bytes(&b)).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("first delivery timed out")
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("second delivery timed out")
        .unwrap();

    assert_eq!(
        first, b"BBBB",
        "B (no delay) overtakes A despite being sent second"
    );
    assert_eq!(
        second, b"AAAA",
        "A arrives second, having been held 200ms by the mix"
    );
}
