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
//! - Parked streams are bounded both by count (`capacity`) and by age: a background reaper
//!   evicts any stream that has waited longer than `parked_ttl` without a peer, so a patient
//!   attacker cannot hold the map full with admitted-but-idle parks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gyre_net::{read_frame, write_frame};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::admission::{Admission, Challenge, Denied, CHALLENGE_LEN};
use crate::effort::EffortController;
use crate::token::{Issuer, Token, OUTPUT_LEN, SEED_LEN};
use crate::Solution;

/// A rendezvous cookie: the shared identifier two parties use to find each other.
pub type Cookie = Vec<u8>;

/// Admission-response modes: the first byte of a client's response selects how it authorizes.
const MODE_POW: u8 = 0x01;
const MODE_TOKEN: u8 = 0x02;

/// A parked stream together with the instant it was parked, so the reaper can evict a stream
/// that has waited longer than `parked_ttl` without a peer.
type Parked = (TcpStream, Instant);

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
    /// The peer presented a cookie longer than the configured maximum.
    #[error("cookie exceeds the maximum length")]
    CookieTooLong,
    /// The relay is already holding `capacity` parked connections.
    #[error("relay at capacity")]
    AtCapacity,
    /// The relay is already processing `max_inflight` admission handshakes.
    #[error("too many in-flight handshakes")]
    TooManyInflight,
    /// The peer's admission response began with an unrecognised mode byte.
    #[error("unknown admission mode")]
    UnknownAdmissionMode,
    /// The peer presented a capability token but this relay was not given a verifier.
    #[error("this relay does not accept capability tokens")]
    TokensNotAccepted,
    /// The capability token was invalid or already spent.
    #[error("capability token rejected (invalid or already spent)")]
    TokenRejected,
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
    /// The largest cookie the relay will accept. The cookie is otherwise bounded only by the
    /// 1 MiB frame limit, which would let a full parking map cost `capacity × 1 MiB`. A tight
    /// cap (cookies are short identifiers) removes that memory-amplification vector.
    pub max_cookie_len: usize,
    /// The maximum number of admission handshakes in progress at once. `handshake_timeout`
    /// bounds each handshake's *duration*; this bounds their *count*, so a flood of
    /// connections that each stall for the full timeout cannot pin an unbounded number of
    /// tasks and sockets. Excess connections are dropped immediately at accept.
    pub max_inflight: usize,
    /// How long a parked (admitted, waiting-for-peer) stream may sit unmet before the relay
    /// evicts it. `capacity` bounds how *many* slots exist; this bounds how *long* one is
    /// held, so a patient attacker who solves the puzzle and parks on every cookie cannot
    /// hold the map — and the load signal it drives — full indefinitely. Must exceed a
    /// legitimate peer's realistic arrival latency.
    pub parked_ttl: Duration,
    /// The window over which the effort controller measures the admission-attempt *rate*.
    pub effort_window: Duration,
    /// Admission attempts per `effort_window` at or below which the relay is calm. Above it,
    /// the effort controller raises difficulty even for a flood that never parks.
    pub effort_target_per_window: u32,
}

/// A rendezvous relay: splices two connections that present the same cookie.
///
/// Created with [`RendezvousRelay::new`] it is **unguarded** — the plain origin-hiding
/// meeting point. Created with [`RendezvousRelay::guarded`] every connection must pass the
/// admission gate first.
#[derive(Clone)]
pub struct RendezvousRelay {
    waiting: Arc<Mutex<HashMap<Cookie, Parked>>>,
    gate: Option<Arc<Mutex<Admission>>>,
    /// Bounds the number of admission handshakes in progress. `None` on an unguarded relay.
    inflight: Option<Arc<Semaphore>>,
    /// Verifies capability tokens for the skip-PoW fast path. `None` means tokens are not
    /// accepted and every client must solve the puzzle.
    verifier: Option<Arc<Mutex<Issuer>>>,
    /// Rate-aware effort controller: raises difficulty for a flood that never parks. `None` on
    /// an unguarded relay.
    effort: Option<Arc<Mutex<EffortController>>>,
    config: RelayConfig,
    start: Instant,
}

impl Default for RendezvousRelay {
    fn default() -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            gate: None,
            inflight: None,
            verifier: None,
            effort: None,
            config: RelayConfig::unbounded(),
            start: Instant::now(),
        }
    }
}

impl RendezvousRelay {
    /// An **unguarded** relay: any connection may park or splice. Origin-hiding only, with
    /// no admission gate and no bounds — the plain meeting point.
    pub fn new() -> Self {
        Self::default()
    }

    /// An **admission-gated** relay. Every connection must solve a load-scaled, single-use,
    /// server-issued puzzle before it can park or splice; the parking map is bounded to
    /// `config.capacity`; handshakes are bounded in both duration (`handshake_timeout`) and
    /// count (`max_inflight`); and cookies are length-capped. This is the configuration that
    /// makes the relay a real L7 gate.
    pub fn guarded(config: RelayConfig) -> Self {
        Self::guarded_inner(config, None)
    }

    /// Shared construction for the two guarded variants, so a new bound cannot be added to one
    /// and forgotten on the other.
    fn guarded_inner(config: RelayConfig, verifier: Option<Arc<Mutex<Issuer>>>) -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            gate: Some(Arc::new(Mutex::new(Admission::new(config.ttl)))),
            inflight: Some(Arc::new(Semaphore::new(config.max_inflight))),
            verifier,
            effort: Some(Arc::new(Mutex::new(EffortController::new(
                config.effort_window,
                config.effort_target_per_window,
            )))),
            config,
            start: Instant::now(),
        }
    }

    /// A guarded relay that **also accepts capability tokens** as a skip-PoW fast path. A
    /// pre-authorized client that holds a valid, unspent token (earned from `issuer`) redeems
    /// it in place of solving the puzzle — the Privacy-Pass model. Everyone else still pays
    /// the PoW. This is what makes the *Authorization* dimension do real work: the token now
    /// gates admission rather than being minted and discarded.
    ///
    /// The `issuer` is shared (redemption mutates its single-use spent set), so one operator
    /// runs both the token issuer and this relay.
    pub fn guarded_with_tokens(config: RelayConfig, issuer: Arc<Mutex<Issuer>>) -> Self {
        Self::guarded_inner(config, Some(issuer))
    }

    /// The effort controller's current suggested load in `[0, 1]`, or `0.0` on an unguarded
    /// relay. Diagnostic — lets an operator watch the rate-driven pressure rise and fall.
    pub fn effort_load(&self) -> f64 {
        match &self.effort {
            Some(e) => e
                .lock()
                .expect("effort controller not poisoned")
                .load(self.start.elapsed()),
            None => 0.0,
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
        // On a guarded relay, sweep stale parks in the background. The sweep runs at half the
        // TTL, so a parked stream lives at most ~1.5×`parked_ttl` before eviction.
        if self.gate.is_some() {
            let waiting = self.waiting.clone();
            let parked_ttl = self.config.parked_ttl;
            let period = (parked_ttl / 2).max(Duration::from_millis(10));
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(period);
                loop {
                    ticker.tick().await;
                    let reaped = reap_stale_parks(&waiting, parked_ttl);
                    if reaped > 0 {
                        eprintln!("[rendezvous] reaped {reaped} stale parked stream(s)");
                    }
                }
            });
        }

        loop {
            let (stream, _peer) = listener.accept().await?;

            // Bound concurrent handshakes: take a permit before spawning, and drop the
            // connection immediately if the gate is already saturated. The permit is held
            // only for the handshake window (dropped in `handle` before park/splice), so
            // long-lived spliced sessions do not consume handshake slots.
            let permit = match &self.inflight {
                Some(sem) => match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        eprintln!(
                            "[rendezvous] connection refused: {}",
                            Error::TooManyInflight
                        );
                        continue;
                    }
                },
                None => None,
            };

            let relay = self.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(relay, permit, stream).await {
                    eprintln!("[rendezvous] connection refused: {e}");
                }
            });
        }
    }
}

impl RelayConfig {
    /// The unguarded configuration: no admission bounds at all. Used by the plain relay.
    fn unbounded() -> Self {
        Self {
            capacity: usize::MAX,
            ttl: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            max_cookie_len: usize::MAX,
            max_inflight: usize::MAX,
            parked_ttl: Duration::from_secs(3600),
            effort_window: Duration::from_secs(1),
            effort_target_per_window: u32::MAX,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            ttl: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            max_cookie_len: 128,
            max_inflight: 256,
            parked_ttl: Duration::from_secs(60),
            effort_window: Duration::from_secs(1),
            effort_target_per_window: 200,
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
///
/// The relay always offers a PoW challenge first; the peer's response begins with a mode byte
/// choosing how it authorizes — [`MODE_POW`] (solve the puzzle) or [`MODE_TOKEN`] (redeem a
/// capability token, if this relay accepts them).
async fn admit(
    gate: &Mutex<Admission>,
    verifier: Option<&Mutex<Issuer>>,
    effort: Option<&Mutex<EffortController>>,
    waiting: &Mutex<HashMap<Cookie, Parked>>,
    config: RelayConfig,
    start: Instant,
    stream: &mut TcpStream,
) -> Result<Cookie> {
    // Price the challenge by the *stronger* of two load signals, so either can raise it:
    //  - parking occupancy, which reacts to a flood that fills the map, and
    //  - the admission-attempt rate, which reacts to a flood that never parks.
    // Issuing is still stateless (the effort controller is O(1) state, not per-challenge).
    let now = start.elapsed();
    let parked = waiting.lock().expect("map not poisoned").len();
    let occupancy_load = load_of(parked, config.capacity);
    let rate_load = match effort {
        Some(e) => {
            let mut e = e.lock().expect("effort controller not poisoned");
            e.record_attempt(now);
            e.load(now)
        }
        None => 0.0,
    };
    let load = occupancy_load.max(rate_load);
    let challenge = gate.lock().expect("gate not poisoned").issue(now, load);
    write_frame(stream, &challenge.to_bytes()).await?;

    let resp = read_frame(stream).await?.ok_or(Error::NoCookie)?;
    let (&mode, body) = resp.split_first().ok_or(Error::MalformedAdmission)?;
    match mode {
        MODE_POW => {
            // body = challenge ‖ nonce ‖ cookie.
            if body.len() < CHALLENGE_LEN + 8 {
                return Err(Error::MalformedAdmission);
            }
            // Cap the cookie before allocating it: otherwise the parked map costs up to
            // `capacity × MAX_FRAME`, a memory-amplification vector a valid solver can hit.
            if body.len() - (CHALLENGE_LEN + 8) > config.max_cookie_len {
                return Err(Error::CookieTooLong);
            }
            let mut challenge_bytes = [0u8; CHALLENGE_LEN];
            challenge_bytes.copy_from_slice(&body[..CHALLENGE_LEN]);
            let returned = Challenge::from_bytes(&challenge_bytes);
            let mut nonce_bytes = [0u8; 8];
            nonce_bytes.copy_from_slice(&body[CHALLENGE_LEN..CHALLENGE_LEN + 8]);
            let solution = Solution {
                nonce: u64::from_be_bytes(nonce_bytes),
                attempts: 0,
            };
            let cookie = body[CHALLENGE_LEN + 8..].to_vec();

            // Redeem against the *server's own* challenge — a forged, downgraded, expired,
            // unsolved, or replayed admission is refused here.
            gate.lock().expect("gate not poisoned").redeem(
                &returned,
                &solution,
                start.elapsed(),
            )?;
            Ok(cookie)
        }
        MODE_TOKEN => {
            // body = token seed ‖ token output ‖ cookie. The fast path for a pre-authorized
            // client: redeem a valid, unspent capability token in place of solving the puzzle.
            let verifier = verifier.ok_or(Error::TokensNotAccepted)?;
            const TOKEN_LEN: usize = SEED_LEN + OUTPUT_LEN;
            if body.len() < TOKEN_LEN {
                return Err(Error::MalformedAdmission);
            }
            if body.len() - TOKEN_LEN > config.max_cookie_len {
                return Err(Error::CookieTooLong);
            }
            let mut seed = [0u8; SEED_LEN];
            seed.copy_from_slice(&body[..SEED_LEN]);
            let mut output = [0u8; OUTPUT_LEN];
            output.copy_from_slice(&body[SEED_LEN..TOKEN_LEN]);
            let token = Token { seed, output };
            let cookie = body[TOKEN_LEN..].to_vec();

            // `redeem` is valid-**and**-unspent-once, so a token authorizes exactly one
            // admission — a stolen or replayed token is refused.
            if !verifier.lock().expect("issuer not poisoned").redeem(&token) {
                return Err(Error::TokenRejected);
            }
            Ok(cookie)
        }
        _ => Err(Error::UnknownAdmissionMode),
    }
}

/// Handle one accepted connection. Takes the whole relay (its fields are all `Arc`/`Copy`, so
/// a clone is cheap) rather than a long argument list.
async fn handle(
    relay: RendezvousRelay,
    permit: Option<OwnedSemaphorePermit>,
    mut stream: TcpStream,
) -> Result<()> {
    // Gate first (if configured), then the cookie logic is identical for both relays.
    //
    // The whole gated handshake is bounded by `handshake_timeout`. Without this deadline a
    // peer that connects, receives the challenge, and then stalls would hold this task and
    // socket forever — the classic slowloris. The bound covers the challenge write and the
    // response read, so a stalled peer is dropped rather than accumulated.
    let cookie_result = match &relay.gate {
        Some(gate) => {
            let handshake = admit(
                gate,
                relay.verifier.as_deref(),
                relay.effort.as_deref(),
                &relay.waiting,
                relay.config,
                relay.start,
                &mut stream,
            );
            match tokio::time::timeout(relay.config.handshake_timeout, handshake).await {
                Ok(result) => result,
                Err(_elapsed) => Err(Error::HandshakeTimeout),
            }
        }
        None => match read_frame(&mut stream).await {
            Ok(Some(cookie)) => Ok(cookie),
            Ok(None) => Err(Error::NoCookie),
            Err(e) => Err(e.into()),
        },
    };
    // The handshake is over: release the in-flight permit now, before the (unbounded-in-time)
    // park/splice phase, so an established session never holds a handshake slot.
    drop(permit);
    let cookie = cookie_result?;

    // Is a peer already parked on this cookie?
    let peer = relay
        .waiting
        .lock()
        .expect("rendezvous map not poisoned")
        .remove(&cookie);
    match peer {
        None => {
            // First to arrive: park for the peer to pick up — but never past capacity, so a
            // flood cannot grow the map without bound even if it solves every puzzle. The
            // park time is recorded so the reaper can evict it if no peer ever arrives.
            let mut map = relay.waiting.lock().expect("rendezvous map not poisoned");
            if map.len() >= relay.config.capacity {
                return Err(Error::AtCapacity);
            }
            map.insert(cookie, (stream, Instant::now()));
            Ok(())
        }
        Some((mut peer, _parked_at)) => {
            // Second to arrive: glue the two together and copy opaque bytes both ways.
            copy_bidirectional(&mut stream, &mut peer).await?;
            Ok(())
        }
    }
}

/// Evict parked streams older than `parked_ttl`, dropping (and so closing) each. Called
/// periodically by the reaper on a guarded relay.
fn reap_stale_parks(waiting: &Mutex<HashMap<Cookie, Parked>>, parked_ttl: Duration) -> usize {
    let now = Instant::now();
    let mut map = waiting.lock().expect("rendezvous map not poisoned");
    let before = map.len();
    map.retain(|_, (_, parked_at)| now.duration_since(*parked_at) < parked_ttl);
    before - map.len()
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

    // Respond: MODE_POW ‖ challenge ‖ nonce ‖ cookie.
    let mut resp = Vec::with_capacity(1 + CHALLENGE_LEN + 8 + cookie.len());
    resp.push(MODE_POW);
    resp.extend_from_slice(&arr);
    resp.extend_from_slice(&solution.nonce.to_be_bytes());
    resp.extend_from_slice(cookie);
    write_frame(&mut stream, &resp).await?;
    Ok(stream)
}

/// Dial a **token-accepting** guarded relay and present a capability `token` in place of
/// solving the puzzle — the skip-PoW fast path for a pre-authorized client. The relay still
/// sends a challenge first (which is ignored) and redeems the token; a valid, unspent token
/// authorizes exactly one admission.
pub async fn dial_with_token(rp: SocketAddr, cookie: &[u8], token: &Token) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(rp).await?;

    // Drain the server's challenge frame; a token client does not solve it.
    let _challenge = read_frame(&mut stream).await?.ok_or(Error::NoCookie)?;

    // Respond: MODE_TOKEN ‖ seed ‖ output ‖ cookie.
    let mut resp = Vec::with_capacity(1 + SEED_LEN + OUTPUT_LEN + cookie.len());
    resp.push(MODE_TOKEN);
    resp.extend_from_slice(&token.seed);
    resp.extend_from_slice(&token.output);
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

        let mut resp = vec![super::MODE_POW];
        resp.extend_from_slice(&challenge_bytes);
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
            handshake_timeout: Duration::from_millis(300),
            ..RelayConfig::default()
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
    async fn a_guarded_relay_refuses_an_oversized_cookie() {
        // A solver that presents a huge cookie would otherwise cost up to capacity × 1 MiB of
        // parked memory. The cap refuses it even though the proof-of-work is valid.
        let config = RelayConfig {
            max_cookie_len: 32,
            ..RelayConfig::default()
        };
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(config).serve(rp_listener));

        // Solve the challenge honestly, then attach an over-long cookie.
        let mut peer = TcpStream::connect(rp_addr).await.unwrap();
        let arr: [u8; CHALLENGE_LEN] = read_frame(&mut peer)
            .await
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();
        let challenge = Challenge::from_bytes(&arr);
        let solution = challenge.puzzle().solve();
        let mut resp = vec![super::MODE_POW];
        resp.extend_from_slice(&arr);
        resp.extend_from_slice(&solution.nonce.to_be_bytes());
        resp.extend_from_slice(&vec![b'x'; 4096]); // way over the 32-byte cap
        write_frame(&mut peer, &resp).await.unwrap();

        let after = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut peer)).await;
        assert!(
            matches!(after, Ok(Ok(None)) | Ok(Err(_))),
            "an over-long cookie must be refused even with a valid solution"
        );
    }

    #[tokio::test]
    async fn a_guarded_relay_bounds_concurrent_handshakes() {
        // max_inflight = 1: one slow handshake holds the only permit, so a second connection
        // is dropped at accept before it ever receives a challenge — bounding the COUNT of
        // in-flight handshakes, not just each one's duration.
        let config = RelayConfig {
            max_inflight: 1,
            handshake_timeout: Duration::from_secs(5),
            ..RelayConfig::default()
        };
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(RendezvousRelay::guarded(config).serve(rp_listener));

        // First connection takes the permit and stalls (never answers the challenge).
        let mut hog = TcpStream::connect(rp_addr).await.unwrap();
        let _challenge = read_frame(&mut hog).await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second connection: the permit is gone, so it is dropped at accept. It must NOT
        // receive a challenge, and must close quickly — well within the 5s handshake window.
        let mut blocked = TcpStream::connect(rp_addr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut blocked)).await;
        assert!(
            matches!(got, Ok(Ok(None)) | Ok(Err(_))),
            "with the in-flight permit held, a second handshake must be dropped at accept, \
             not served a challenge"
        );
    }

    #[tokio::test]
    async fn a_token_relay_admits_a_valid_token_and_refuses_a_replay() {
        use crate::token::{blind, unblind, Issuer};

        // The operator runs the issuer and a token-accepting relay off the same issuer.
        let issuer = Arc::new(Mutex::new(Issuer::new()));

        // A client earns a token: solve an issuance puzzle, mint, unblind. (F14.)
        let token = {
            let mut iss = issuer.lock().unwrap();
            let published = iss.public_key();
            let now = Duration::from_secs(0);
            let (state, blinded) = blind();
            let challenge = iss.issuance_challenge(now);
            let solution = challenge.puzzle().solve();
            let issued = iss.issue(&challenge, &solution, blinded, now).unwrap();
            unblind(state, issued, published).unwrap()
        };

        let relay = RendezvousRelay::guarded_with_tokens(RelayConfig::default(), issuer);
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(relay.serve(rp_listener));

        // An origin parks (via the ordinary PoW path); the token-bearing client reaches it.
        let cookie = b"token-cookie".to_vec();
        let origin_cookie = cookie.clone();
        let origin = tokio::spawn(async move {
            let mut s = dial_admitted(rp_addr, &origin_cookie).await.unwrap();
            let req = read_frame(&mut s).await.unwrap().unwrap();
            let mut r = b"pong: ".to_vec();
            r.extend_from_slice(&req);
            write_frame(&mut s, &r).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = dial_with_token(rp_addr, &cookie, &token).await.unwrap();
        write_frame(&mut client, b"ping").await.unwrap();
        let reply = read_frame(&mut client).await.unwrap().unwrap();
        assert_eq!(
            reply, b"pong: ping",
            "a valid token admits without solving the puzzle"
        );
        origin.await.unwrap();

        // The SAME token is single-use: a replay is refused (the relay never splices it).
        let replay = tokio::time::timeout(
            Duration::from_secs(2),
            dial_with_token(rp_addr, &cookie, &token),
        )
        .await;
        if let Ok(Ok(mut s)) = replay {
            // The connection may open, but the relay must not admit it — no reply comes back.
            let _ = write_frame(&mut s, b"ping-again").await;
            let got = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut s)).await;
            assert!(
                matches!(got, Ok(Ok(None)) | Ok(Err(_))),
                "a replayed (already-spent) token must be refused, not admitted"
            );
        }
    }

    #[tokio::test]
    async fn a_guarded_relay_reaps_a_parked_stream_that_is_never_met() {
        // A patient attacker solves the puzzle and parks, but no peer ever arrives. capacity
        // caps how many such squatters fit; parked_ttl caps how long each holds its slot.
        let config = RelayConfig {
            parked_ttl: Duration::from_millis(200),
            ..RelayConfig::default()
        };
        let relay = RendezvousRelay::guarded(config);
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        tokio::spawn(relay.clone().serve(rp_listener));

        // Park an origin and never send it a client.
        let _squatter = dial_admitted(rp_addr, b"unmet-cookie").await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            relay.parked(),
            1,
            "the solved-and-parked stream should occupy a slot"
        );

        // After the TTL (plus the reaper's half-TTL sweep period and margin), the slot is freed.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            relay.parked(),
            0,
            "a parked stream unmet past parked_ttl must be reaped, freeing the slot"
        );
    }

    #[tokio::test]
    async fn a_flood_of_attempts_that_never_park_raises_the_difficulty() {
        // Every probe connects, reads the challenge, and drops — so it makes an admission
        // *attempt* but never parks and never occupies a slot. With an occupancy-only signal
        // the difficulty would stay at the floor; the rate-aware effort controller raises it.
        let config = RelayConfig {
            effort_window: Duration::from_millis(50),
            effort_target_per_window: 2,
            ..RelayConfig::default()
        };
        let rp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rp_addr = rp_listener.local_addr().unwrap();
        let relay = RendezvousRelay::guarded(config);
        tokio::spawn(relay.clone().serve(rp_listener));

        // Read the difficulty the relay offers a fresh connection (which then drops).
        async fn probe_difficulty(addr: std::net::SocketAddr) -> u32 {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let bytes = read_frame(&mut s).await.unwrap().unwrap();
            let arr: [u8; CHALLENGE_LEN] = bytes.as_slice().try_into().unwrap();
            Challenge::from_bytes(&arr).difficulty_bits()
            // drop `s` -> never responds, never parks
        }

        let baseline = probe_difficulty(rp_addr).await;

        // Flood across several windows, each far above the target of 2 attempts/window.
        for _ in 0..6 {
            for _ in 0..10 {
                let _ = probe_difficulty(rp_addr).await;
            }
            tokio::time::sleep(Duration::from_millis(60)).await; // cross a window boundary
        }

        let under_flood = probe_difficulty(rp_addr).await;
        assert!(
            under_flood > baseline,
            "a flood of attempts that never park must raise the difficulty via the rate signal \
             (under flood {under_flood} bits vs baseline {baseline}); effort load = {:.2}",
            relay.effort_load()
        );
    }

    #[tokio::test]
    async fn a_guarded_relay_never_parks_beyond_capacity() {
        // Capacity 2: a third distinct-cookie origin that solves its puzzle must still be
        // refused a slot, so a flood cannot grow the map without bound.
        let config = RelayConfig {
            capacity: 2,
            ..RelayConfig::default()
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
