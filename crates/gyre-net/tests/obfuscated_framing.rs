//! Obfuscated framing over a real socket. These tests prove `gyre-obfs` now **touches a
//! socket** — the fabric's bytes are reshaped on the wire, not merely transformable in a
//! library — and that the payload round-trips. They do *not* claim unblockability: obfuscation
//! is appearance only (the honest ceiling on `gyre-obfs`).

use gyre_net::{read_frame, read_frame_obfuscated, write_frame_obfuscated};
use gyre_obfs::{shannon_entropy_bits_per_byte, Obfuscator, Polymorphic, TlsMimic};
use tokio::net::{TcpListener, TcpStream};

/// Send one obfuscated frame across a real TCP connection and return the **raw** wire bytes
/// as the other end sees them (before de-obfuscation), so a test can inspect the disguise.
async fn wire_bytes(obfs: &dyn Obfuscator, payload: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    write_frame_obfuscated(&mut client, obfs, payload)
        .await
        .unwrap();
    read_frame(&mut server).await.unwrap().unwrap()
}

#[tokio::test]
async fn tls_mimic_puts_a_tls_record_header_on_the_wire() {
    let obfs = TlsMimic;
    let payload = b"gyre onion payload, which is not TLS at all";
    let wire = wire_bytes(&obfs, payload).await;

    assert_ne!(
        &wire[..],
        &payload[..],
        "the wire bytes must be reshaped, not the plaintext payload"
    );
    assert_eq!(
        &wire[..3],
        &[0x17, 0x03, 0x03],
        "TlsMimic must emit a TLS application-data record header (17 03 03)"
    );
    assert_eq!(
        obfs.deobfuscate(&wire).unwrap(),
        payload,
        "and the exact payload must be recoverable"
    );
}

#[tokio::test]
async fn polymorphic_makes_the_wire_look_like_uniform_random_bytes() {
    let obfs = Polymorphic::new([7u8; 32]);
    let payload = vec![0x00u8; 512]; // deliberately zero-entropy plaintext

    let wire = wire_bytes(&obfs, &payload).await;
    assert_ne!(
        wire, payload,
        "low-entropy input must not pass through unchanged"
    );

    let h = shannon_entropy_bits_per_byte(&wire);
    assert!(
        h > 7.0,
        "a 'looks-like-nothing' transport should make the wire near-uniform-random; \
         got {h:.2} bits/byte from an all-zero payload"
    );
    assert_eq!(obfs.deobfuscate(&wire).unwrap(), payload);
}

#[tokio::test]
async fn a_full_obfuscated_round_trip_over_a_socket_recovers_the_payload() {
    let obfs = Polymorphic::new([9u8; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();

    write_frame_obfuscated(&mut client, &obfs, b"ping through the disguise")
        .await
        .unwrap();
    let got = read_frame_obfuscated(&mut server, &obfs)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"ping through the disguise");
}

#[tokio::test]
async fn the_wrong_transport_key_fails_to_deobfuscate_rather_than_returning_garbage() {
    // Polymorphic authenticates its keystream, so a peer with the wrong key must get an
    // error, not silently-wrong plaintext.
    let sender = Polymorphic::new([1u8; 32]);
    let wire = wire_bytes(&sender, b"secret").await;
    let wrong = Polymorphic::new([2u8; 32]);
    assert!(
        wrong.deobfuscate(&wire).is_err(),
        "a mismatched transport key must fail, not return corrupted bytes"
    );
}
