//! Authenticated rendezvous: the mutual-auth handshake that closes the bearer-cookie
//! session-hijack race. A party that learned only the relay-facing rendezvous ID cannot
//! complete it; only a party that knows the cookie can.

use gyre_cli::{authenticate, rendezvous_id, AuthError};
use gyre_net::{read_frame, write_frame};
use tokio::net::{TcpListener, TcpStream};

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[test]
fn the_rendezvous_id_hides_the_cookie_and_is_deterministic() {
    let cookie = b"a shared rendezvous cookie";
    let id = rendezvous_id(cookie);
    assert_eq!(id, rendezvous_id(cookie), "the ID must be deterministic");
    assert_ne!(id, cookie, "the ID must not equal the cookie");
    assert_ne!(
        rendezvous_id(b"other cookie"),
        id,
        "different cookies must yield different IDs"
    );
}

#[tokio::test]
async fn honest_peers_authenticate_and_then_exchange_a_message() {
    let (mut c, mut s) = pair().await;
    let cookie: &[u8] = b"real-cookie";

    let origin = tokio::spawn(async move {
        let sess = authenticate(&mut s, cookie, false).await.unwrap();
        (s, sess)
    });
    let mut client_sess = authenticate(&mut c, cookie, true).await.unwrap();
    let (mut s, mut origin_sess) = origin.await.unwrap();

    // The session returned by the handshake works end to end.
    client_sess
        .send(&mut c, b"hello, authenticated")
        .await
        .unwrap();
    let got = origin_sess.recv(&mut s).await.unwrap().unwrap();
    assert_eq!(got, b"hello, authenticated");
}

#[tokio::test]
async fn the_origin_rejects_a_hijacker_that_forges_the_client_tag() {
    // The strong case: an attacker who learned the rendezvous ID (so it could race the splice)
    // but not the cookie. It runs the protocol and forges its final tag; the honest origin must
    // reject it rather than establish a session.
    let (mut c, mut s) = pair().await;
    let origin = tokio::spawn(async move {
        authenticate(&mut s, b"real-cookie", false)
            .await
            .map(|_| ())
    });

    // Attacker, by hand: send a nonce, read the origin's (nonce ‖ tag), send a bogus tag.
    write_frame(&mut c, &[7u8; 32]).await.unwrap();
    let _resp = read_frame(&mut c).await.unwrap().unwrap();
    write_frame(&mut c, &[0u8; 32]).await.unwrap(); // a tag it cannot compute without the cookie

    let origin_res = origin.await.unwrap();
    assert!(
        matches!(origin_res, Err(AuthError::PeerNotAuthenticated)),
        "the origin must reject a forged client tag, got {origin_res:?}"
    );
}

#[tokio::test]
async fn a_client_rejects_an_origin_with_the_wrong_cookie() {
    // Symmetric: a client detects an impostor origin (wrong cookie) and does not proceed.
    let (mut c, mut s) = pair().await;
    let impostor = tokio::spawn(async move {
        // Impostor origin knows a different cookie.
        let _ = authenticate(&mut s, b"wrong-cookie", false).await;
    });
    let client_res = authenticate(&mut c, b"real-cookie", true).await.map(|_| ());
    // On failure the real caller drops the stream; closing it lets the impostor's dangling
    // read return rather than block forever.
    drop(c);
    let _ = impostor.await;
    assert!(
        matches!(client_res, Err(AuthError::PeerNotAuthenticated)),
        "the client must reject an origin that cannot prove the cookie, got {client_res:?}"
    );
}
