//! **Rendezvous origin-hiding.**
//!
//! The origin of a protected service publishes *no* inbound address. Instead it dials
//! *out* to a rendezvous relay and waits there behind a shared cookie. A client dials
//! the same relay with the same cookie, and the relay **splices** the two connections,
//! copying opaque bytes between them until they close.
//!
//! The relay is a meeting point, not a middlebox: it never learns either endpoint's
//! location (the origin only ever made an *outbound* connection) and it never sees the
//! content (in the full design the client↔origin bytes are end-to-end encrypted, so the
//! relay copies ciphertext). This is the property Cloudflare structurally cannot offer —
//! but note the honest ceiling (**D22**): it protects a *closed* set of parties who share
//! the cookie, and the relay pool still needs to survive volumetric load.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use whirl_net::{read_frame, write_frame};

/// A rendezvous cookie: the shared identifier two parties use to find each other.
pub type Cookie = Vec<u8>;

/// Errors from the rendezvous relay or dialing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Net(#[from] whirl_net::Error),
    #[error("peer connected without sending a cookie")]
    NoCookie,
}

/// Convenience alias for results from this module.
pub type Result<T> = std::result::Result<T, Error>;

/// A rendezvous relay: splices two connections that present the same cookie.
#[derive(Clone, Default)]
pub struct RendezvousRelay {
    waiting: Arc<Mutex<HashMap<Cookie, TcpStream>>>,
}

impl RendezvousRelay {
    /// A fresh relay with no waiting connections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve forever on `listener`, splicing matched pairs.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let waiting = self.waiting.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(waiting, stream).await {
                    eprintln!("[rendezvous] connection error: {e}");
                }
            });
        }
    }
}

async fn handle(
    waiting: Arc<Mutex<HashMap<Cookie, TcpStream>>>,
    mut stream: TcpStream,
) -> Result<()> {
    let cookie = read_frame(&mut stream).await?.ok_or(Error::NoCookie)?;

    // Is a peer already parked on this cookie?
    let peer = waiting
        .lock()
        .expect("rendezvous map not poisoned")
        .remove(&cookie);
    match peer {
        None => {
            // First to arrive: park our (post-cookie) stream for the peer to pick up.
            // The task ends, but the stream lives in the map until the peer takes it.
            waiting
                .lock()
                .expect("rendezvous map not poisoned")
                .insert(cookie, stream);
            Ok(())
        }
        Some(mut peer) => {
            // Second to arrive: glue the two together and copy opaque bytes both ways.
            copy_bidirectional(&mut stream, &mut peer).await?;
            Ok(())
        }
    }
}

/// Dial a rendezvous relay at `rp` and present `cookie`, returning the connected stream.
///
/// Both the origin (dialing *out*, so it never publishes an inbound address) and the
/// client use this; whoever arrives second is spliced to the first.
pub async fn dial(rp: SocketAddr, cookie: &[u8]) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(rp).await?;
    write_frame(&mut stream, cookie).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn origin_dials_out_and_a_client_reaches_it_via_the_meeting_point() {
        // Start the rendezvous relay.
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::new().serve(rp_listener));

        let cookie = b"a shared rendezvous cookie".to_vec();

        // The origin dials OUT (never listens for inbound) and answers one request.
        let origin_cookie = cookie.clone();
        let origin = tokio::spawn(async move {
            let mut stream = dial(rp_addr, &origin_cookie).await.unwrap();
            let request = read_frame(&mut stream).await.unwrap().unwrap();
            let mut response = b"origin answers: ".to_vec();
            response.extend_from_slice(&request);
            write_frame(&mut stream, &response).await.unwrap();
        });

        // The client reaches the origin through the relay.
        let mut client = dial(rp_addr, &cookie).await.unwrap();
        write_frame(&mut client, b"hello origin").await.unwrap();
        let response = read_frame(&mut client).await.unwrap().unwrap();

        assert_eq!(response, b"origin answers: hello origin");
        origin.await.unwrap();
    }
}
