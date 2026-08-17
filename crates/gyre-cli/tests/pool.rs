//! Multi-relay pool failover: a client reaches the origin through a survivor when another
//! relay in the pool is dead. This exercises the real components (a guarded relay, admission,
//! the mutual-auth handshake, per-relay rendezvous IDs) with the same failover logic the
//! `gyre-reach` binary uses.

use std::net::SocketAddr;
use std::time::Duration;

use gyre_cli::{authenticate, rendezvous_id_for};
use gyre_shield::rendezvous::{dial_admitted, RelayConfig, RendezvousRelay};
use tokio::net::TcpListener;

#[tokio::test]
async fn a_client_fails_over_to_a_live_relay_when_one_is_dead() {
    let cookie: &[u8] = b"pool-cookie";

    // A live guarded relay.
    let live_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_addr = live_listener.local_addr().unwrap();
    tokio::spawn(RendezvousRelay::guarded(RelayConfig::default()).serve(live_listener));

    // A "dead" relay: bind then drop the listener, so its address refuses connections.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    // The origin parks on the live relay (authenticated).
    tokio::spawn(async move {
        let key = rendezvous_id_for(cookie, &live_addr);
        loop {
            let Ok(mut stream) = dial_admitted(live_addr, &key).await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(mut session) = authenticate(&mut stream, cookie, false).await else {
                continue;
            };
            if let Ok(Some(request)) = session.recv(&mut stream).await {
                let mut reply = b"pong: ".to_vec();
                reply.extend_from_slice(&request);
                let _ = session.send(&mut stream, &reply).await;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Client failover: try the dead relay FIRST (it refuses fast), then the live one.
    let pool: [SocketAddr; 2] = [dead_addr, live_addr];
    let mut reached: Option<Vec<u8>> = None;
    for &rzv in &pool {
        let key = rendezvous_id_for(cookie, &rzv);
        let attempt = async {
            let mut stream = dial_admitted(rzv, &key).await.ok()?;
            let mut session = authenticate(&mut stream, cookie, true).await.ok()?;
            session.send(&mut stream, b"hi").await.ok()?;
            session.recv(&mut stream).await.ok().flatten()
        };
        if let Ok(Some(reply)) = tokio::time::timeout(Duration::from_secs(3), attempt).await {
            reached = Some(reply);
            break;
        }
    }

    assert_eq!(
        reached.as_deref(),
        Some(b"pong: hi".as_slice()),
        "the client must reach the origin via the live relay after the dead one is skipped"
    );
}
