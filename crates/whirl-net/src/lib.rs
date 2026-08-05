//! **Milestone S1 — a Sphinx onion carried over the network.**
//!
//! S0 proved the onion works in memory. S1 turns each relay into an asynchronous
//! server that receives an onion off the wire, unwraps one layer, and forwards the
//! rest to the next hop's *network* address — so a packet really travels
//! client → relay → relay → exit → destination, and no relay ever learns both ends.
//!
//! The transport here is length-prefixed frames over async TCP: the smallest thing
//! that is genuinely networked, so we can build mixing (S2) and multipath (S3) on a
//! real async substrate. The QUIC/MASQUE transport upgrade (per-circuit streams,
//! censorship-resistant framing) is a later milestone; everything here is written
//! against a small surface so that swap is contained.
//!
//! Addressing: the Sphinx layer routes by opaque address *labels*; a [`Directory`]
//! maps each label to a real socket address. In the full design the directory is
//! the decentralized, threshold-signed consensus (Add 4); here it is an in-memory
//! map for a local testnet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use whirl_sphinx::{
    exponential_delays, exponential_interval, null_surb, packet_from_bytes, packet_to_bytes,
    wrap_with_delays, Node, Relay, Unwrapped, ADDRESS_LEN, DEST_ADDRESS_LEN,
};

/// Largest frame we will read, as a denial-of-service guard. Real onion packets
/// are a few kilobytes; this is generous headroom.
pub const MAX_FRAME: usize = 1 << 20; // 1 MiB

/// Errors from the transport / relay layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sphinx: {0}")]
    Sphinx(#[from] whirl_sphinx::Error),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("address not found in directory")]
    UnknownAddress,
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Wire framing: a u32 big-endian length prefix followed by that many bytes.
// ---------------------------------------------------------------------------

/// Write one length-prefixed frame and flush it.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::FrameTooLarge(bytes.len()))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame. Returns `Ok(None)` on a clean end-of-stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(Error::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

// ---------------------------------------------------------------------------
// Directory: label -> socket address (relays and destinations share the space).
// ---------------------------------------------------------------------------

/// Maps Sphinx address labels to the socket addresses that serve them.
///
/// Immutable once built (a snapshot of the network), so it is cheap to clone into
/// every relay task.
#[derive(Clone, Default)]
pub struct Directory(Arc<HashMap<[u8; ADDRESS_LEN], SocketAddr>>);

impl Directory {
    /// Build a directory from `(label, address)` entries.
    pub fn from_entries(
        entries: impl IntoIterator<Item = ([u8; ADDRESS_LEN], SocketAddr)>,
    ) -> Self {
        Self(Arc::new(entries.into_iter().collect()))
    }

    /// Resolve a label to its socket address.
    pub fn lookup(&self, label: &[u8; ADDRESS_LEN]) -> Option<SocketAddr> {
        self.0.get(label).copied()
    }
}

/// Connect to `addr` and send one framed message (used by the client for the first
/// hop, and internally to forward between relays).
pub async fn send_to(addr: SocketAddr, bytes: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    write_frame(&mut stream, bytes).await?;
    stream.shutdown().await.ok();
    Ok(())
}

/// Wrap `payload` in a Sphinx onion through `route` — with an exponential per-hop
/// mixing delay of mean `per_hop_mean` — to `dest`, and send it to `first_hop`.
///
/// This is the per-fragment send used by multipath (S3): the caller loops over
/// disjoint paths, one fragment each.
pub async fn send_onion(
    first_hop: SocketAddr,
    route: &[Node],
    dest: [u8; DEST_ADDRESS_LEN],
    payload: &[u8],
    per_hop_mean: Duration,
) -> Result<()> {
    let delays = exponential_delays(route.len(), per_hop_mean);
    let packet = wrap_with_delays(payload, route, dest, null_surb(), &delays)?;
    send_to(first_hop, &packet_to_bytes(&packet)).await
}

// ---------------------------------------------------------------------------
// Cover traffic (Loopix loops).
// ---------------------------------------------------------------------------

/// Emit `count` Loopix-style "loop" packets at exponential intervals (mean
/// `interval`) through `route` to a client-controlled `loop_dest`.
///
/// Each loop is a fixed-size Sphinx packet indistinguishable on the wire from real
/// traffic, so relays cannot tell cover from payload; the stream of loops is what
/// makes an idle user look like an active one and inflates the effective anonymity
/// set. In the full design a loop returns to the sender via a SURB so the client can
/// notice dropped/blocked packets; here it routes to a loop sink the client owns.
pub async fn emit_loops(
    first_hop: SocketAddr,
    route: &[Node],
    loop_dest: [u8; DEST_ADDRESS_LEN],
    interval: Duration,
    per_hop_delay: Duration,
    count: usize,
) -> Result<()> {
    const COVER_MARKER: &[u8] = b"whirlpool-cover-loop";
    for _ in 0..count {
        tokio::time::sleep(exponential_interval(interval)).await;
        let delays = exponential_delays(route.len(), per_hop_delay);
        let packet = wrap_with_delays(COVER_MARKER, route, loop_dest, null_surb(), &delays)?;
        send_to(first_hop, &packet_to_bytes(&packet)).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Relay server: accept onions, unwrap one layer, forward or deliver.
// ---------------------------------------------------------------------------

/// An async relay: it listens for onions, processes each with its own key, and
/// forwards to the next hop (or delivers the plaintext to the destination).
pub struct RelayServer {
    relay: Arc<Relay>,
    dir: Directory,
    verbose: bool,
}

impl RelayServer {
    /// Create a relay server for `relay`, resolving next hops via `dir`.
    pub fn new(relay: Relay, dir: Directory) -> Self {
        Self {
            relay: Arc::new(relay),
            dir,
            verbose: false,
        }
    }

    /// Print each forward/deliver to stderr (for the demo). Off by default.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Serve forever on `listener`, spawning a task per connection.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let RelayServer {
            relay,
            dir,
            verbose,
        } = self;
        loop {
            let (stream, _peer) = listener.accept().await?;
            let relay = relay.clone();
            let dir = dir.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(relay, dir, stream, verbose).await {
                    eprintln!("[relay] connection error: {e}");
                }
            });
        }
    }
}

async fn handle_conn(
    relay: Arc<Relay>,
    dir: Directory,
    mut stream: TcpStream,
    verbose: bool,
) -> Result<()> {
    while let Some(frame) = read_frame(&mut stream).await? {
        let packet = packet_from_bytes(&frame)?;
        match relay.process(packet)? {
            Unwrapped::Forward {
                next_address,
                packet,
                delay_nanos,
            } => {
                let next = dir.lookup(&next_address).ok_or(Error::UnknownAddress)?;
                if verbose {
                    eprintln!(
                        "[relay #{}] hold {}ms -> forward to #{}",
                        relay.address()[0],
                        delay_nanos / 1_000_000,
                        next_address[0]
                    );
                }
                // Loopix-style mixing: hold the packet for its per-hop exponential
                // delay before forwarding, so packets arriving in one order can
                // leave in another and an observer cannot match them by timing.
                if delay_nanos > 0 {
                    tokio::time::sleep(Duration::from_nanos(delay_nanos)).await;
                }
                send_to(next, &packet_to_bytes(&packet)).await?;
            }
            Unwrapped::Final {
                dest_address,
                payload,
            } => {
                let dest = dir.lookup(&dest_address).ok_or(Error::UnknownAddress)?;
                if verbose {
                    eprintln!(
                        "[relay #{}] EXIT -> deliver {} bytes to dest #{}",
                        relay.address()[0],
                        payload.len(),
                        dest_address[0]
                    );
                }
                send_to(dest, &payload).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_round_trips() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let msg = vec![7u8; 1000];
        let expected = msg.clone();
        tokio::spawn(async move {
            write_frame(&mut client, &expected).await.unwrap();
        });
        let got = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let (client, mut server) = tokio::io::duplex(16);
        drop(client);
        assert!(read_frame(&mut server).await.unwrap().is_none());
    }
}
