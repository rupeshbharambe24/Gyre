//! **Rendezvous origin-hiding**, optionally behind an **admission gate**.
//!
//! The origin of a protected service publishes *no* inbound address. Instead it dials
//! *out* to a rendezvous relay and waits there behind a shared cookie. A client dials
//! the same relay with the same cookie, and the relay **splices** the two connections,
//! copying opaque bytes between them until they close.
//!
//! The relay is a meeting point, not a middlebox: it never learns either endpoint's
//! location (the origin only ever made an *outbound* connection). This is the property a
//! reverse-proxy CDN structurally cannot offer.
//!
//! ## The admission gate — what makes the relay a real L7 defence
//!
//! A bare rendezvous relay accepts any connection and parks it, so a flood of connections
//! exhausts its memory and slots for free. [`RendezvousRelay::guarded`] puts the
//! [`Admission`](crate::admission::Admission) protocol in front of **every** connection:
//! before a peer may park or splice, the relay makes it solve a **server-issued, expiring,
//! single-use** proof-of-work whose difficulty rises with how full the relay is. The relay
//! verifies each admission in one HMAC plus one hash; the attacker pays the whole cost.
//!
//! The parking map is also **bounded** to a capacity, and that same capacity is the load
//! signal: `load = parked / capacity`. So a flood that fills the relay drives the puzzle to
//! its maximum difficulty and then is refused outright — while a legitimate client at low
//! load pays the ~256-hash floor, which is microseconds.
//!
//! ## Honest ceilings
//!
//! - This prices **application-layer** admission. It does **nothing** against a volumetric
//!   L3/L4 flood that saturates the link before this code runs — that is capacity (anycast
//!   scrubbing), which Gyre neither has nor claims (**D22**).
//! - The cookie is still an **unauthenticated bearer secret**: admission controls *how many*
//!   connections get in, not *who* they are, so a party that learns a cookie can still race
//!   the legitimate client for the parked peer. Authenticating the cookie is separate work.
//! - Parked streams are bounded by count but not yet evicted by age: a slow origin that
//!   parks and is never met holds its slot until it disconnects. The capacity bound caps the
//!   total; a TTL reaper is not implemented.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gyre_net::{read_frame, write_frame};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

use crate::admission::{Admission, Challenge, Denied, CHALLENGE_LEN};
use crate::Solution;

/// A rendezvous cookie: the shared identifier two parties use to find each other.
pub type Cookie = Vec<u8>;

/// Errors from the rendezvous relay or dialing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Net(#[from] gyre_net::Error),
    #[error("peer connected without sending a cookie")]
    NoCookie,
    /// The peer failed the admission gate.
    #[error("admission denied: {0}")]
    Admission(#[from] Denied),
    /// The peer's admission response was too short to contain a challenge and a nonce.
    #[error("malformed admission response")]
    MalformedAdmission,
    /// The peer did not complete the admission handshake within the deadline (slowloris).
    #[error("admission handshake timed out")]
    HandshakeTimeout,
    /// The relay is already holding `capacity` parked connections.
    #[error("relay at capacity")]
    AtCapacity,
}

/// Convenience alias for results from this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Configuration for an admission-gated relay.
#[derive(Clone, Copy, Debug)]
pub struct RelayConfig {
    /// Maximum number of simultaneously parked connections. Bounds memory, and is the
    /// denominator of the load signal that scales puzzle difficulty.
    pub capacity: usize,
    /// How long an issued admission challenge stays valid.
    pub ttl: Duration,
    /// How long the relay will wait for a connection to complete the admission handshake
    /// before dropping it. This is the **slowloris** bound: without it, a peer that opens a
    /// connection and then never sends its solution pins a task and a socket indefinitely.
    /// It must comfortably exceed a legitimate client's worst-case solve-plus-round-trip.
    pub handshake_timeout: Duration,
}

/// A rendezvous relay: splices two connections that present the same cookie.
///
/// Created with [`RendezvousRelay::new`] it is **unguarded** — the plain origin-hiding
/// meeting point. Created with [`RendezvousRelay::guarded`] every connection must pass the
/// admission gate first.
#[derive(Clone)]
pub struct RendezvousRelay {
    waiting: Arc<Mutex<HashMap<Cookie, TcpStream>>>,
    gate: Option<Arc<Mutex<Admission>>>,
    capacity: usize,
    handshake_timeout: Duration,
    start: Instant,
}

impl Default for RendezvousRelay {
    fn default() -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            gate: None,
            capacity: usize::MAX,
            handshake_timeout: Duration::from_secs(10),
            start: Instant::now(),
        }
    }
}

impl RendezvousRelay {
    /// An **unguarded** relay: any connection may park or splice. Origin-hiding only.
    pub fn new() -> Self {
        Self::default()
    }

    /// An **admission-gated** relay. Every connection must solve a load-scaled, single-use,
    /// server-issued puzzle before it can park or splice, and the parking map is bounded to
    /// `config.capacity`. This is the configuration that makes the relay a real L7 gate.
    pub fn guarded(config: RelayConfig) -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            gate: Some(Arc::new(Mutex::new(Admission::new(config.ttl)))),
            capacity: config.capacity,
            handshake_timeout: config.handshake_timeout,
            start: Instant::now(),
        }
    }

    /// How many connections are currently parked. Diagnostic — lets a caller watch the
    /// bound hold under load.
    pub fn parked(&self) -> usize {
        self.waiting
            .lock()
            .expect("rendezvous map not poisoned")
            .len()
    }

    /// Serve forever on `listener`, splicing matched pairs.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let waiting = self.waiting.clone();
            let gate = self.gate.clone();
            let capacity = self.capacity;
            let handshake_timeout = self.handshake_timeout;
            let start = self.start;
            tokio::spawn(async move {
                if let Err(e) =
                    handle(waiting, gate, capacity, handshake_timeout, start, stream).await
                {
                    eprintln!("[rendezvous] connection refused: {e}");
                }
            });
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            ttl: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// The current load, in `[0, 1]`, as parked-connections over capacity.
fn load_of(parked: usize, capacity: usize) -> f64 {
    if capacity == 0 || capacity == usize::MAX {
        return 0.0;
    }
    (parked as f64 / capacity as f64).min(1.0)
}

/// Run the admission handshake as the server. Returns the cookie carried in the peer's
/// authenticated response, or an error that denies the connection.
async fn admit(
    gate: &Mutex<Admission>,
    waiting: &Mutex<HashMap<Cookie, TcpStream>>,
    capacity: usize,
    start: Instant,
    stream: &mut TcpStream,
) -> Result<Cookie> {
    // Price the challenge by current load. Issuing is stateless, so this costs one HMAC
    // even under a flood of connections that never finish.
    let parked = waiting.lock().expect("map not poisoned").len();
    let load = load_of(parked, capacity);
    let now = start.elapsed();
    let challenge = gate.lock().expect("gate not poisoned").issue(now, load);
    write_frame(stream, &challenge.to_bytes()).await?;

    // The peer returns: challenge ‖ nonce ‖ cookie.
    let resp = read_frame(stream).await?.ok_or(Error::NoCookie)?;
    if resp.len() < CHALLENGE_LEN + 8 {
        return Err(Error::MalformedAdmission);
    }
    let mut challenge_bytes = [0u8; CHALLENGE_LEN];
    challenge_bytes.copy_from_slice(&resp[..CHALLENGE_LEN]);
    let returned = Challenge::from_bytes(&challenge_bytes);
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&resp[CHALLENGE_LEN..CHALLENGE_LEN + 8]);
    let solution = Solution {
        nonce: u64::from_be_bytes(nonce_bytes),
        attempts: 0,
    };
    let cookie = resp[CHALLENGE_LEN + 8..].to_vec();

    // Redeem against the *server's own* challenge — this is where a forged, downgraded,
    // expired, unsolved, or replayed admission is refused. `now` is re-read so a puzzle that
    // took real time to solve is still judged against the same clock.
    gate.lock()
        .expect("gate not poisoned")
        .redeem(&returned, &solution, start.elapsed())?;
    Ok(cookie)
}

async fn handle(
    waiting: Arc<Mutex<HashMap<Cookie, TcpStream>>>,
    gate: Option<Arc<Mutex<Admission>>>,
    capacity: usize,
    handshake_timeout: Duration,
    start: Instant,
    mut stream: TcpStream,
) -> Result<()> {
    // Gate first (if configured), then the cookie logic is identical for both relays.
    //
    // The whole gated handshake is bounded by `handshake_timeout`. Without this deadline a
    // peer that connects, receives the challenge, and then stalls would hold this task and
    // socket forever — the classic slowloris. The bound covers the challenge write and the
    // response read, so a stalled peer is dropped rather than accumulated.
    let cookie = match &gate {
        Some(gate) => {
            let handshake = admit(gate, &waiting, capacity, start, &mut stream);
            match tokio::time::timeout(handshake_timeout, handshake).await {
                Ok(result) => result?,
                Err(_elapsed) => return Err(Error::HandshakeTimeout),
            }
        }
        None => read_frame(&mut stream).await?.ok_or(Error::NoCookie)?,
    };

    // Is a peer already parked on this cookie?
    let peer = waiting
        .lock()
        .expect("rendezvous map not poisoned")
        .remove(&cookie);
    match peer {
        None => {
            // First to arrive: park for the peer to pick up — but never past capacity, so a
            // flood cannot grow the map without bound even if it solves every puzzle.
            let mut map = waiting.lock().expect("rendezvous map not poisoned");
            if map.len() >= capacity {
                return Err(Error::AtCapacity);
            }
            map.insert(cookie, stream);
            Ok(())
        }
        Some(mut peer) => {
            // Second to arrive: glue the two together and copy opaque bytes both ways.
            copy_bidirectional(&mut stream, &mut peer).await?;
            Ok(())
        }
    }
}

/// Dial an **unguarded** rendezvous relay at `rp` and present `cookie`.
///
/// Both the origin (dialing *out*, so it never publishes an inbound address) and the
/// client use this; whoever arrives second is spliced to the first.
pub async fn dial(rp: SocketAddr, cookie: &[u8]) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(rp).await?;
    write_frame(&mut stream, cookie).await?;
    Ok(stream)
}

/// Dial an **admission-gated** relay: read its challenge, solve the puzzle, and present the
/// solution together with the cookie. Returns the connected stream once admitted.
///
/// The proof-of-work solve is CPU-bound, so it runs on a blocking thread rather than
/// stalling the async runtime.
pub async fn dial_admitted(rp: SocketAddr, cookie: &[u8]) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(rp).await?;

    // Receive the server's challenge.
    let challenge_bytes = read_frame(&mut stream).await?.ok_or(Error::NoCookie)?;
    let arr: [u8; CHALLENGE_LEN] = challenge_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedAdmission)?;
    let challenge = Challenge::from_bytes(&arr);

    // Solve it off the runtime.
    let puzzle = challenge.puzzle();
    let solution = tokio::task::spawn_blocking(move || puzzle.solve())
        .await
        .expect("solve task panicked");

    // Respond: challenge ‖ nonce ‖ cookie.
    let mut resp = Vec::with_capacity(CHALLENGE_LEN + 8 + cookie.len());
    resp.extend_from_slice(&arr);
    resp.extend_from_slice(&solution.nonce.to_be_bytes());
    resp.extend_from_slice(cookie);
    write_frame(&mut stream, &resp).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn origin_dials_out_and_a_client_reaches_it_via_the_meeting_point() {
        // The unguarded relay: pure origin-hiding.
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::new().serve(rp_listener));

        let cookie = b"a shared rendezvous cookie".to_vec();

        let origin_cookie = cookie.clone();
        let origin = tokio::spawn(async move {
            let mut stream = dial(rp_addr, &origin_cookie).await.unwrap();
            let request = read_frame(&mut stream).await.unwrap().unwrap();
            let mut response = b"origin answers: ".to_vec();
            response.extend_from_slice(&request);
            write_frame(&mut stream, &response).await.unwrap();
        });

        let mut client = dial(rp_addr, &cookie).await.unwrap();
        write_frame(&mut client, b"hello origin").await.unwrap();
        let response = read_frame(&mut client).await.unwrap().unwrap();

        assert_eq!(response, b"origin answers: hello origin");
        origin.await.unwrap();
    }

    #[tokio::test]
    async fn a_guarded_relay_admits_a_client_that_solves_the_puzzle() {
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(RelayConfig::default()).serve(rp_listener));

        let cookie = b"guarded cookie".to_vec();

        let origin_cookie = cookie.clone();
        let origin = tokio::spawn(async move {
            let mut stream = dial_admitted(rp_addr, &origin_cookie).await.unwrap();
            let request = read_frame(&mut stream).await.unwrap().unwrap();
            let mut response = b"pong: ".to_vec();
            response.extend_from_slice(&request);
            write_frame(&mut stream, &response).await.unwrap();
        });

        // Give the origin a moment to park.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = dial_admitted(rp_addr, &cookie).await.unwrap();
        write_frame(&mut client, b"ping").await.unwrap();
        let response = read_frame(&mut client).await.unwrap().unwrap();

        assert_eq!(
            response, b"pong: ping",
            "an admitted client reaches the origin"
        );
        origin.await.unwrap();
    }

    #[tokio::test]
    async fn a_guarded_relay_refuses_a_connection_that_skips_the_puzzle() {
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(RelayConfig::default()).serve(rp_listener));

        // An attacker that ignores the admission protocol: connect and immediately send a
        // cookie, as the *unguarded* dial would. The server issues a challenge (ignored),
        // then reads this frame, cannot parse a challenge+nonce out of it, and drops the
        // connection. The attacker sees EOF, never a splice.
        let mut attacker = TcpStream::connect(rp_addr).await.unwrap();
        write_frame(&mut attacker, b"no proof of work here")
            .await
            .unwrap();
        // Drain the server's challenge frame (if it arrived) then confirm the connection is
        // closed rather than serving us.
        let _ = read_frame(&mut attacker).await; // the challenge, or EOF
                                                 // Bounded: a refused connection is closed (read resolves to None) quickly; a wrongly
                                                 // admitted one would park and this read would block, so a timeout is a test failure.
        let after = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut attacker)).await;
        assert!(
            matches!(after, Ok(Ok(None)) | Ok(Err(_))),
            "the relay must drop a peer that does not solve the puzzle, not serve or park it"
        );
    }

    #[tokio::test]
    async fn a_guarded_relay_refuses_a_well_formed_admission_that_fails_redeem() {
        // The attacker speaks the protocol correctly — challenge ‖ nonce ‖ cookie, right
        // lengths — but corrupts the challenge id so its authentication tag no longer
        // verifies. This drives `redeem` specifically (a `Denied::Forged`), not the length
        // guard, so the test fails if the gate is wired without actually calling `redeem`.
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(RelayConfig::default()).serve(rp_listener));

        let mut attacker = TcpStream::connect(rp_addr).await.unwrap();
        let mut challenge_bytes = read_frame(&mut attacker).await.unwrap().unwrap();
        challenge_bytes[0] ^= 0xFF; // corrupt the id → the server's tag will not match

        let mut resp = challenge_bytes;
        resp.extend_from_slice(&0u64.to_be_bytes());
        resp.extend_from_slice(b"cookie");
        write_frame(&mut attacker, &resp).await.unwrap();

        // Bounded read: refusal closes the connection promptly; a bypassed `redeem` would
        // park this forged admission and the read would block until the timeout — which the
        // assertion treats as failure, so the test catches a gate wired without redeem.
        let after = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut attacker)).await;
        assert!(
            matches!(after, Ok(Ok(None)) | Ok(Err(_))),
            "a forged (tampered) challenge must be refused by redeem, not admitted or parked"
        );
    }

    #[tokio::test]
    async fn a_guarded_relay_drops_a_slowloris_that_never_finishes_the_handshake() {
        // A slowloris: connect, take the challenge, then never send the solution. Without a
        // handshake deadline this pins a task and socket forever. With one, the relay drops
        // it and the connection closes shortly after the deadline.
        let config = RelayConfig {
            capacity: 8,
            ttl: Duration::from_secs(30),
            handshake_timeout: Duration::from_millis(300),
        };
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(config).serve(rp_listener));

        let mut slowloris = TcpStream::connect(rp_addr).await.unwrap();
        let _challenge = read_frame(&mut slowloris).await.unwrap().unwrap();
        // Deliberately send nothing further. The server must drop us after the deadline.
        let after = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut slowloris)).await;
        assert!(
            matches!(after, Ok(Ok(None)) | Ok(Err(_))),
            "a peer that stalls the handshake must be dropped after the deadline, not held"
        );
    }

    #[tokio::test]
    async fn a_guarded_relay_never_parks_beyond_capacity() {
        // Capacity 2: a third distinct-cookie origin that solves its puzzle must still be
        // refused a slot, so a flood cannot grow the map without bound.
        let config = RelayConfig {
            capacity: 2,
            ttl: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
        };
        let relay = RendezvousRelay::guarded(config);
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(relay.clone().serve(rp_listener));

        // Three origins park on three different cookies. Each solves the (low-load) puzzle.
        for i in 0..3u8 {
            let cookie = vec![b'c', i];
            let _ = dial_admitted(rp_addr, &cookie).await.unwrap();
            // small gap so the server processes the park before the next dial
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        tokio::time::sleep(Duration::from_millis(60)).await;

        assert!(
            relay.parked() <= 2,
            "parked = {} must never exceed the capacity of 2",
            relay.parked()
        );
    }
}
