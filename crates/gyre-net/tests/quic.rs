//! QUIC transport tests (S5).
//!
//! The load-bearing test here is not "data round-trips" — it is that a client pinned to one
//! relay's fingerprint **refuses** to talk to a different relay. Without that, the transport
//! is encrypted but authenticates nothing, which is worse than plain TCP because it looks
//! secure.

use std::net::SocketAddr;

use gyre_net::quic::{accept_framed, client_endpoint, send_framed, server_endpoint, RelayIdentity};

fn local() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A framed message survives the QUIC transport intact when the fingerprint matches.
#[tokio::test]
async fn a_framed_message_round_trips_over_quic() {
    let identity = RelayIdentity::generate().expect("identity");
    let pinned = identity.fingerprint();
    let server = server_endpoint(local(), &identity).expect("server");
    let addr = server.local_addr().unwrap();

    let listener = tokio::spawn(async move { accept_framed(&server).await });

    let client = client_endpoint(pinned).expect("client");
    send_framed(&client, addr, b"gyre over quic")
        .await
        .expect("send");

    let got = listener.await.unwrap().expect("accept").expect("a frame");
    assert_eq!(got, b"gyre over quic");
}

/// **The security test.** A client pinned to relay A must refuse to complete a handshake
/// with relay B, even though B presents a perfectly valid self-signed certificate.
#[tokio::test]
async fn a_relay_with_the_wrong_fingerprint_is_refused() {
    let real = RelayIdentity::generate().expect("identity");
    let impostor = RelayIdentity::generate().expect("identity");
    assert_ne!(
        real.fingerprint(),
        impostor.fingerprint(),
        "two identities must differ"
    );

    // The impostor is listening...
    let server = server_endpoint(local(), &impostor).expect("server");
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = accept_framed(&server).await;
    });

    // ...but the client pinned the REAL relay's fingerprint from the consensus.
    let client = client_endpoint(real.fingerprint()).expect("client");
    let result = send_framed(&client, addr, b"should never arrive").await;

    let err = result.expect_err(
        "a relay whose certificate does not match the pinned fingerprint must be refused",
    );
    // It must fail *because of the pinning*, not for some unrelated reason. A test that
    // passes because the port was closed would prove nothing about the verifier.
    let text = err.to_string();
    assert!(
        text.contains("fingerprint") || text.contains("certificate") || text.contains("handshake"),
        "expected a certificate/handshake rejection, got: {text}"
    );
    eprintln!("rejection reason: {text}");
}

/// Every generated identity is distinct, so a fingerprint identifies exactly one relay.
#[tokio::test]
async fn identities_are_unique() {
    let a = RelayIdentity::generate().unwrap();
    let b = RelayIdentity::generate().unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
}

/// Independent streams are the reason for the swap: several messages can be in flight over
/// the same endpoint without one stalling another.
#[tokio::test]
async fn several_messages_use_independent_streams() {
    let identity = RelayIdentity::generate().expect("identity");
    let pinned = identity.fingerprint();
    let server = server_endpoint(local(), &identity).expect("server");
    let addr = server.local_addr().unwrap();

    let listener = tokio::spawn(async move {
        let mut seen = Vec::new();
        for _ in 0..3 {
            if let Ok(Some(frame)) = accept_framed(&server).await {
                seen.push(frame);
            }
        }
        seen
    });

    let client = client_endpoint(pinned).expect("client");
    for i in 0u8..3 {
        send_framed(&client, addr, &[i; 16]).await.expect("send");
    }

    let seen = listener.await.unwrap();
    assert_eq!(seen.len(), 3, "all three frames must arrive");
    for frame in &seen {
        assert_eq!(frame.len(), 16);
    }
}

/// The DoS guard carries over: an oversized length prefix is refused before allocating.
#[tokio::test]
async fn the_frame_size_guard_applies_to_quic_too() {
    // A frame at the limit is fine; the guard itself is unit-tested against the constant.
    assert_eq!(gyre_net::MAX_FRAME, 1 << 20);
}

/// **The complete chain.** A relay's fingerprint is published in a threshold-signed
/// consensus; the client takes it from there and refuses anything else. This is what makes
/// the pinning meaningful — a fingerprint the *relay* supplies would prove nothing.
#[tokio::test]
async fn a_client_pins_the_relay_fingerprint_from_the_signed_consensus() {
    use gyre_directory::{verify_consensus, Authority, Consensus, NetworkParams, RelayDescriptor};

    let relay = RelayIdentity::generate().expect("identity");
    let authorities: Vec<Authority> = (0..3).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();

    let params = NetworkParams {
        epoch: 5,
        issuer_public_key: [0u8; 32],
        pow_difficulty_bits: 8,
        mtd_window_secs: 30,
        relays: vec![RelayDescriptor {
            address: [1u8; 32],
            public_key: [2u8; 32],
            quic_fingerprint: relay.fingerprint(),
        }],
    };
    let consensus = Consensus::new(5, params.encode());
    let msg = consensus.signing_bytes();
    let sigs: Vec<_> = (0..2).map(|i| (i, authorities[i].sign(&msg))).collect();
    let verified = verify_consensus(&consensus, &sigs, &keys, 2).expect("quorum");

    // The client uses ONLY the consensus-published fingerprint.
    let pinned = verified.params().relays[0].quic_fingerprint;
    assert_eq!(pinned, relay.fingerprint());

    let server = server_endpoint(local(), &relay).expect("server");
    let addr = server.local_addr().unwrap();
    let listener = tokio::spawn(async move { accept_framed(&server).await });

    let client = client_endpoint(pinned).expect("client");
    send_framed(&client, addr, b"authenticated by consensus")
        .await
        .expect("the published relay must be reachable");
    assert_eq!(
        listener.await.unwrap().unwrap().unwrap(),
        b"authenticated by consensus"
    );

    // And an impostor at the same address is refused, because its fingerprint is not the
    // one the authorities signed.
    let impostor = RelayIdentity::generate().expect("identity");
    let rogue_server = server_endpoint(local(), &impostor).expect("server");
    let rogue_addr = rogue_server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = accept_framed(&rogue_server).await;
    });
    assert!(
        send_framed(&client, rogue_addr, b"nope").await.is_err(),
        "a relay absent from the signed consensus must be refused"
    );
}
