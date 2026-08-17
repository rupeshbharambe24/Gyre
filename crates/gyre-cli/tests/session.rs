//! Forward-secret, compartmentalized sessions over a real socket. Proves the Persistence
//! mechanism is *wired*: each message is keyed by a fresh ratchet key (forward secrecy), and
//! a session for a different context cannot read another's traffic (compartmentalization).

use gyre_cli::Session;
use gyre_net::read_frame;
use tokio::net::{TcpListener, TcpStream};

/// A connected client/server TcpStream pair.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn a_session_exchanges_multiple_messages_and_the_origin_recovers_each() {
    let (mut c, mut s) = pair().await;
    let mut client = Session::new(b"cookie", "default", true);
    let mut origin = Session::new(b"cookie", "default", false);

    for msg in [b"one".as_slice(), b"two", b"three"] {
        client.send(&mut c, msg).await.unwrap();
        let got = origin.recv(&mut s).await.unwrap().unwrap();
        assert_eq!(
            got, msg,
            "each message must be recovered under its own ratchet key"
        );
    }
}

#[tokio::test]
async fn each_message_is_keyed_freshly_so_the_wire_differs_for_identical_plaintext() {
    // Send the SAME plaintext twice; because each message advances the ratchet, the wire bytes
    // must differ — the forward-secrecy signal (no key reuse across messages).
    let (mut c, mut s) = pair().await;
    let mut client = Session::new(b"cookie", "default", true);

    client.send(&mut c, b"identical").await.unwrap();
    let wire1 = read_frame(&mut s).await.unwrap().unwrap();
    client.send(&mut c, b"identical").await.unwrap();
    let wire2 = read_frame(&mut s).await.unwrap().unwrap();

    assert_ne!(
        wire1, wire2,
        "identical plaintext under a ratchet must produce different wire bytes (fresh key each message)"
    );
}

#[tokio::test]
async fn a_different_context_cannot_read_another_contexts_traffic() {
    // Compartmentalization: an origin session for "banking" cannot de-obfuscate a client
    // session for "social" — the per-context personas yield unlinkable keys.
    let (mut c, mut s) = pair().await;
    let mut client = Session::new(b"cookie", "social", true);
    let mut wrong = Session::new(b"cookie", "banking", false);

    client.send(&mut c, b"private").await.unwrap();
    // Wrong context -> the keystream does not match -> de-obfuscation fails (Polymorphic
    // authenticates its keystream), rather than returning wrong plaintext.
    let got = wrong.recv(&mut s).await;
    assert!(
        got.is_err(),
        "a session for a different context must fail to read the traffic, not decode garbage"
    );
}
