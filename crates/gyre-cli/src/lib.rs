//! Shared setup for the standalone `gyre-relay` and `gyre-client` binaries.
//!
//! Everything before this point ran inside one process. These binaries are the first that
//! bind real sockets and talk to *other processes*, which is what a network simulator
//! (Shadow) and any real deployment both require.
//!
//! # Testnet key derivation — read this before deploying anything
//!
//! Relay keys here are derived from the relay's public label with a fixed, published
//! salt, so every process agrees on every key with no distribution step. That makes a
//! testnet trivial to launch and reproduce.
//!
//! **It also means every key is public.** Anyone who knows a label can compute that
//! relay's secret key and decrypt its layer. This is acceptable — and only acceptable —
//! for simulation and local testing, where there is nothing to protect. A real deployment
//! must generate secrets from the OS CSPRNG and publish only the *public* halves through
//! the threshold-signed consensus (`gyre-directory::NetworkParams`).

use std::net::SocketAddr;

use gyre_endpoint::Ratchet;
use gyre_net::{read_frame, read_frame_obfuscated, write_frame, write_frame_obfuscated};
use gyre_obfs::{Identity, Obfuscator, Polymorphic, TlsMimic};
use gyre_sphinx::{Relay, ADDRESS_LEN};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

/// Keyed HMAC-SHA256 over a sequence of parts.
fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        m.update(part);
    }
    m.finalize().into_bytes().into()
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS RNG");
    b
}

/// Salt for testnet key derivation. Published on purpose: these keys are not secret.
const TESTNET_SALT: &[u8] = b"gyre-testnet-relay-key/INSECURE-SIMULATION-ONLY";

/// Turn a short human label ("r1") into the fixed-width Sphinx address.
pub fn label_to_address(label: &str) -> [u8; ADDRESS_LEN] {
    let mut addr = [0u8; ADDRESS_LEN];
    let digest = Sha256::digest(label.as_bytes());
    addr.copy_from_slice(&digest[..ADDRESS_LEN.min(32)]);
    addr
}

/// Derive a relay's testnet keypair from its label. **Insecure by design** — see the
/// module docs.
pub fn testnet_relay(label: &str) -> Relay {
    let mut hasher = Sha256::new();
    hasher.update(TESTNET_SALT);
    hasher.update(label.as_bytes());
    let secret: [u8; 32] = hasher.finalize().into();
    Relay::from_secret_bytes(label_to_address(label), secret)
}

/// One `label=host:port` entry from the command line.
#[derive(Clone, Debug)]
pub struct PeerArg {
    pub label: String,
    pub addr: SocketAddr,
}

/// Parse repeated `--relay label=host:port` arguments.
pub fn parse_relays(args: &[String]) -> Result<Vec<PeerArg>, String> {
    let mut peers = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg != "--relay" {
            continue;
        }
        let spec = it.next().ok_or("--relay needs label=host:port")?;
        let (label, addr) = spec
            .split_once('=')
            .ok_or_else(|| format!("malformed --relay {spec:?}, expected label=host:port"))?;
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("bad address in --relay {spec:?}: {e}"))?;
        peers.push(PeerArg {
            label: label.to_string(),
            addr,
        });
    }
    Ok(peers)
}

/// Read a `--flag value` argument.
pub fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

/// Read **every** value of a repeated `--flag value` argument, in order. Used for a relay pool
/// (`--rendezvous a --rendezvous b ...`).
pub fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

/// A per-relay rendezvous ID for a **pool**: distinct for each relay, so a colluding subset of
/// relays cannot recognise that they are hosting the same service by a shared cookie. Both the
/// client and the origin derive it from the shared cookie and the relay's address.
pub fn rendezvous_id_for(cookie: &[u8], relay: &SocketAddr) -> Vec<u8> {
    mac(
        cookie,
        &[b"gyre/rendezvous-id/pool/v1", relay.to_string().as_bytes()],
    )
    .to_vec()
}

/// A random visiting order over `n` relays: a random first choice, then a fixed rotation. This
/// spreads clients' first-choice load across the pool while still trying every relay on failover.
pub fn visiting_order(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let start = usize::from_le_bytes({
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&random32()[..4]);
        b
    }) % n;
    (0..n).map(|i| (start + i) % n).collect()
}

/// Read and parse a typed `--flag value`, or fall back to `default` when the flag is absent.
///
/// A flag that is *present but unparseable* is a configuration error, not a silent fallback —
/// a daemon started with `--capacity abc` should refuse to run, not quietly serve at the
/// default and leave the operator wondering.
pub fn flag_or<T>(args: &[String], name: &str, default: T) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match flag(args, name) {
        None => Ok(default),
        Some(value) => value.parse().map_err(|e| format!("{name} {value:?}: {e}")),
    }
}

/// An LSB-steganography transport: embeds the payload in the low bits of a **generated**
/// cover, so the mechanism runs over a real socket. It implements [`Obfuscator`] so it plugs
/// into the same framing path as the other transports.
///
/// > **Honest ceiling — this is a *mechanism* demonstration, not deniability.** Real
/// > deniability needs an *innocuous real cover* (a photo, audio) that the fabric does not
/// > carry; the synthetic cover here is not innocuous, and LSB steganography is detectable by
/// > standard steganalysis. It also expands the payload **~8×** on the wire (one secret bit
/// > per cover byte). So this covers the *plumbing*, not the *Existence* dimension's goal.
struct StegoTransport;

impl Obfuscator for StegoTransport {
    fn obfuscate(&self, inner: &[u8]) -> Vec<u8> {
        // A cover exactly large enough: the 32-bit length header plus one byte per secret bit.
        let cover_len = gyre_stego::LENGTH_HEADER_BITS + inner.len() * 8;
        let cover = vec![0x80u8; cover_len];
        gyre_stego::embed(&cover, inner).expect("cover sized from fits() precondition")
    }
    fn deobfuscate(&self, wire: &[u8]) -> gyre_obfs::Result<Vec<u8>> {
        gyre_stego::extract(wire).map_err(|_| gyre_obfs::Error::Malformed)
    }
    fn name(&self) -> &'static str {
        "stego-lsb"
    }
}

// ---------------------------------------------------------------------------
// Forward-secret, compartmentalized sessions — the Persistence dimension, wired.
// ---------------------------------------------------------------------------

/// Derive a 32-byte sub-key by labelling a key.
fn subkey(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(label);
    hasher.finalize().into()
}

/// A **forward-secret, per-context** session between a client and an origin, layered over the
/// obfuscated framing. It wires `gyre-endpoint`'s ratchet and compartmentalized personas into
/// real traffic: each message is keyed by a fresh ratchet key (so a captured key reveals only
/// that one message), and the whole session is derived from a per-`context` persona (so a
/// client's activity in one context is cryptographically unlinkable from another).
///
/// Both ends derive identical ratchets from the shared cookie and context; `client_side`
/// only selects which direction is outgoing.
///
/// > **Honest ceilings (per `gyre-endpoint`).** Isolation *contains* a compromise; it cannot
/// > make an untrusted endpoint trusted — a live keylogger reads plaintext regardless. Forward
/// > secrecy protects *past* messages after a key is captured, not an *actively* compromised
/// > endpoint. This is data-minimization and cross-context unlinkability, not endpoint
/// > invincibility.
pub struct Session {
    send: Ratchet,
    recv: Ratchet,
}

impl Session {
    /// A session for `context`, keyed from the shared `cookie`.
    pub fn new(cookie: &[u8], context: &str, client_side: bool) -> Self {
        // A compartmentalized per-context persona: two contexts yield unlinkable keys.
        let master: [u8; 32] = Sha256::digest(cookie).into();
        let persona = gyre_endpoint::Identity::new(master).persona(context);
        Self::from_seed(persona.key(), client_side)
    }

    /// A session from an explicit 32-byte seed (e.g. one produced by the authenticated
    /// rendezvous handshake). `client_side` selects which direction is outgoing.
    pub fn from_seed(seed: [u8; 32], client_side: bool) -> Self {
        let c2o = Ratchet::new(subkey(&seed, b"gyre-session/client-to-origin"));
        let o2c = Ratchet::new(subkey(&seed, b"gyre-session/origin-to-client"));
        if client_side {
            Self {
                send: c2o,
                recv: o2c,
            }
        } else {
            Self {
                send: o2c,
                recv: c2o,
            }
        }
    }

    /// Send one message under the next forward-secret key.
    pub async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        payload: &[u8],
    ) -> Result<(), gyre_net::Error> {
        let key = self.send.next_message_key();
        write_frame_obfuscated(w, &Polymorphic::new(key), payload).await
    }

    /// Receive one message under the next forward-secret key. `Ok(None)` on clean EOF.
    pub async fn recv<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> Result<Option<Vec<u8>>, gyre_net::Error> {
        let key = self.recv.next_message_key();
        read_frame_obfuscated(r, &Polymorphic::new(key)).await
    }
}

// ---------------------------------------------------------------------------
// Authenticated rendezvous — close the bearer-cookie session-hijack race.
// ---------------------------------------------------------------------------

/// The **relay-facing rendezvous ID**: what a client/origin presents to the relay to be
/// matched, derived from the shared `cookie` by a one-way HMAC.
///
/// This is the fix for the bearer-cookie hijack: the relay (and anyone observing it) sees only
/// this ID, never the cookie. An attacker who learns the ID can still race the splice — but the
/// mutual [`authenticate`] handshake below then requires proving knowledge of the *cookie*,
/// which the ID does not reveal, so the hijack fails. (Leaking the cookie itself is
/// unavoidable — it is the shared secret; this closes the far more realistic leak of the
/// relay-visible matching value.)
pub fn rendezvous_id(cookie: &[u8]) -> Vec<u8> {
    mac(cookie, &[b"gyre/rendezvous-id/v1"]).to_vec()
}

/// Why an authenticated rendezvous failed.
#[derive(Debug)]
pub enum AuthError {
    /// A transport error during the handshake.
    Io(gyre_net::Error),
    /// The peer could not prove it knows the cookie — a hijacker who learned only the
    /// rendezvous ID, or simply the wrong party.
    PeerNotAuthenticated,
    /// The peer closed before completing the handshake, or sent a malformed message.
    Incomplete,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Io(e) => write!(f, "transport: {e}"),
            AuthError::PeerNotAuthenticated => {
                write!(
                    f,
                    "peer failed to prove knowledge of the cookie (possible hijack)"
                )
            }
            AuthError::Incomplete => write!(f, "authentication handshake incomplete"),
        }
    }
}

impl From<gyre_net::Error> for AuthError {
    fn from(e: gyre_net::Error) -> Self {
        AuthError::Io(e)
    }
}

const AUTH_TAG_LEN: usize = 32;

/// Mutually authenticate the spliced peer over `stream`: both sides prove knowledge of
/// `cookie` by MACing two fresh nonces, and derive a fresh forward-secret [`Session`] on
/// success. Fails with [`AuthError::PeerNotAuthenticated`] if the peer cannot prove it knows
/// the cookie — which is exactly what stops a party that learned only the rendezvous ID from
/// hijacking the session.
///
/// The nonces make the session seed fresh per connection, so a recorded handshake reveals no
/// reusable key.
pub async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cookie: &[u8],
    client_side: bool,
) -> Result<Session, AuthError> {
    let my_nonce = random32();
    let (nonce_c, nonce_o);

    if client_side {
        // Client speaks first with its nonce, then verifies the origin's tag, then answers.
        write_frame(stream, &my_nonce).await?;
        let resp = read_frame(stream).await?.ok_or(AuthError::Incomplete)?;
        if resp.len() != 32 + AUTH_TAG_LEN {
            return Err(AuthError::Incomplete);
        }
        nonce_c = my_nonce;
        let mut n = [0u8; 32];
        n.copy_from_slice(&resp[..32]);
        nonce_o = n;
        let tag_o = &resp[32..];
        let expected_o = mac(cookie, &[b"origin", &nonce_c, &nonce_o]);
        if expected_o.ct_eq(tag_o).unwrap_u8() != 1 {
            return Err(AuthError::PeerNotAuthenticated);
        }
        let tag_c = mac(cookie, &[b"client", &nonce_c, &nonce_o]);
        write_frame(stream, &tag_c).await?;
    } else {
        // Origin reads the client's nonce, answers with its nonce + tag, then verifies.
        let cn = read_frame(stream).await?.ok_or(AuthError::Incomplete)?;
        if cn.len() != 32 {
            return Err(AuthError::Incomplete);
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(&cn);
        nonce_c = n;
        nonce_o = my_nonce;
        let tag_o = mac(cookie, &[b"origin", &nonce_c, &nonce_o]);
        let mut resp = nonce_o.to_vec();
        resp.extend_from_slice(&tag_o);
        write_frame(stream, &resp).await?;
        let tag_c = read_frame(stream).await?.ok_or(AuthError::Incomplete)?;
        let expected_c = mac(cookie, &[b"client", &nonce_c, &nonce_o]);
        if expected_c.ct_eq(&tag_c).unwrap_u8() != 1 {
            return Err(AuthError::PeerNotAuthenticated);
        }
    }

    let seed = mac(cookie, &[b"session-seed", &nonce_c, &nonce_o]);
    Ok(Session::from_seed(seed, client_side))
}

// ---------------------------------------------------------------------------
// Private directory retrieval (PIR) — the Access-pattern dimension, wired.
// ---------------------------------------------------------------------------

/// A demo directory record for index `i`. **Deterministic and demo-only**, so two server
/// processes hold identical records with no distribution step — the same simulation-only
/// convenience as the testnet relay keys. A real deployment replicates the *signed consensus*
/// records, not these.
pub fn demo_record(i: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"gyre-pir-demo-record/v1");
    hasher.update((i as u64).to_be_bytes());
    hasher.finalize().to_vec()
}

/// Serve 2-server IT-PIR answers forever: read a query mask (one byte per record, non-zero =
/// selected), reply with the XOR of the selected records. A single server sees only a
/// uniformly random mask, so it never learns which record the client wanted.
pub async fn serve_pir(
    listener: tokio::net::TcpListener,
    dir: std::sync::Arc<gyre_pir::Directory>,
) -> std::io::Result<()> {
    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let dir = dir.clone();
        tokio::spawn(async move {
            if let Ok(Some(mask)) = gyre_net::read_frame(&mut stream).await {
                let query: Vec<bool> = mask.iter().map(|&b| b != 0).collect();
                let answer = dir.answer(&query);
                let _ = gyre_net::write_frame(&mut stream, &answer).await;
            }
        });
    }
}

/// Privately fetch record `target` from an `n`-record directory replicated on the two servers
/// `dir_a` and `dir_b`, without either server learning `target`.
///
/// > **Honest ceiling.** The privacy is information-theoretic **only if the two servers do not
/// > collude** — and Sybil infrastructure is in the threat model, which is exactly an attack
/// > on that assumption. It is also **off by default** in practice: every client downloading
/// > the *identical* signed consensus already leaks nothing and is cheaper. Reserve PIR for
/// > the one lookup whose target genuinely leaks (a rendezvous descriptor).
pub async fn pir_lookup(
    dir_a: SocketAddr,
    dir_b: SocketAddr,
    n: usize,
    target: usize,
) -> Result<Vec<u8>, String> {
    let (query_a, query_b) = gyre_pir::build_queries(n, target);
    let answer_a = pir_query_one(dir_a, &query_a).await?;
    let answer_b = pir_query_one(dir_b, &query_b).await?;
    Ok(gyre_pir::recover(&answer_a, &answer_b))
}

/// Send one query mask to one server and read its answer.
async fn pir_query_one(server: SocketAddr, query: &[bool]) -> Result<Vec<u8>, String> {
    let mask: Vec<u8> = query.iter().map(|&b| u8::from(b)).collect();
    let mut stream = tokio::net::TcpStream::connect(server)
        .await
        .map_err(|e| format!("connect {server}: {e}"))?;
    gyre_net::write_frame(&mut stream, &mask)
        .await
        .map_err(|e| format!("send query to {server}: {e}"))?;
    gyre_net::read_frame(&mut stream)
        .await
        .map_err(|e| format!("read answer from {server}: {e}"))?
        .ok_or_else(|| format!("{server} closed without answering"))
}

/// Select a pluggable transport (obfuscator) by name, keyed from the shared `cookie` so both
/// ends agree on the disguise without a separate key exchange.
///
/// Honest ceiling: this reshapes what the *payload* looks like on the wire — appearance only,
/// with **zero** effect on anonymity. "Unblockable" is impossible; obfuscation buys "more
/// expensive to block today", and uniform-random output is itself a DPI fingerprint. The
/// `stego` option is a mechanism demo only — see [`StegoTransport`].
pub fn obfuscator(name: &str, cookie: &[u8]) -> Result<Box<dyn Obfuscator + Send + Sync>, String> {
    match name {
        "identity" | "none" => Ok(Box::new(Identity)),
        "polymorphic" | "poly" => {
            let key: [u8; 32] = Sha256::digest(cookie).into();
            Ok(Box::new(Polymorphic::new(key)))
        }
        "tls" | "tls-mimic" => Ok(Box::new(TlsMimic)),
        "stego" | "stego-lsb" => Ok(Box::new(StegoTransport)),
        other => Err(format!(
            "unknown --obfs {other:?} (expected identity | polymorphic | tls | stego)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_keys_are_reproducible_across_processes() {
        // The whole point: two independently started processes derive the same key.
        assert_eq!(
            testnet_relay("r1").public_key().as_bytes(),
            testnet_relay("r1").public_key().as_bytes()
        );
        assert_ne!(
            testnet_relay("r1").public_key().as_bytes(),
            testnet_relay("r2").public_key().as_bytes()
        );
    }

    #[test]
    fn labels_map_to_distinct_addresses() {
        assert_ne!(label_to_address("r1"), label_to_address("r2"));
        assert_eq!(label_to_address("r1"), label_to_address("r1"));
    }

    #[test]
    fn relay_args_parse() {
        let args: Vec<String> = [
            "--relay",
            "r1=127.0.0.1:9001",
            "--relay",
            "r2=127.0.0.1:9002",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let peers = parse_relays(&args).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].label, "r1");
        assert_eq!(peers[1].addr.port(), 9002);
    }

    #[test]
    fn a_malformed_relay_arg_is_an_error_not_a_panic() {
        let args = vec!["--relay".to_string(), "no-equals-sign".to_string()];
        assert!(parse_relays(&args).is_err());
    }

    #[test]
    fn a_pool_rendezvous_id_is_distinct_per_relay_and_deterministic() {
        let cookie = b"pool-cookie";
        let a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        assert_eq!(rendezvous_id_for(cookie, &a), rendezvous_id_for(cookie, &a));
        assert_ne!(
            rendezvous_id_for(cookie, &a),
            rendezvous_id_for(cookie, &b),
            "each relay in the pool must see a distinct ID"
        );
        assert_ne!(rendezvous_id_for(cookie, &a), a.to_string().into_bytes());
    }

    #[test]
    fn visiting_order_is_a_permutation_covering_every_relay() {
        for n in [1usize, 2, 3, 7] {
            let order = visiting_order(n);
            assert_eq!(order.len(), n);
            let mut seen = order.clone();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), n, "every relay must appear exactly once");
            assert!(order.iter().all(|&i| i < n));
        }
        assert!(visiting_order(0).is_empty());
    }

    #[test]
    fn obfuscator_selects_by_name_and_rejects_unknown() {
        let cookie = b"shared-cookie";
        assert_eq!(obfuscator("identity", cookie).unwrap().name(), "identity");
        assert!(obfuscator("polymorphic", cookie).is_ok());
        assert!(obfuscator("tls", cookie).is_ok());
        assert!(obfuscator("nope", cookie).is_err());

        // Same cookie -> same Polymorphic keystream, so a round trip recovers the payload.
        let a = obfuscator("polymorphic", cookie).unwrap();
        let b = obfuscator("polymorphic", cookie).unwrap();
        let wire = a.obfuscate(b"hello");
        assert_ne!(wire, b"hello", "the disguise must transform the bytes");
        assert_eq!(b.deobfuscate(&wire).unwrap(), b"hello");
    }

    #[test]
    fn stego_transport_embeds_and_recovers_with_the_expected_expansion() {
        let s = obfuscator("stego", b"cookie").unwrap();
        assert_eq!(s.name(), "stego-lsb");
        let payload = b"hidden in the low bits";
        let wire = s.obfuscate(payload);
        // Honest cost: ~8x expansion (one secret bit per cover byte) plus a 32-byte header.
        assert_eq!(
            wire.len(),
            gyre_stego::LENGTH_HEADER_BITS + payload.len() * 8,
            "LSB stego expands the payload ~8x — a real wire cost"
        );
        assert_eq!(s.deobfuscate(&wire).unwrap(), payload, "and it round-trips");
    }

    #[test]
    fn flag_or_parses_uses_default_and_rejects_garbage() {
        let args: Vec<String> = ["--capacity", "512"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // present and valid
        assert_eq!(flag_or::<usize>(&args, "--capacity", 1024).unwrap(), 512);
        // absent -> default
        assert_eq!(flag_or::<usize>(&args, "--missing", 1024).unwrap(), 1024);
        // present but garbage -> error, not a silent default
        let bad: Vec<String> = ["--capacity", "abc"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(flag_or::<usize>(&bad, "--capacity", 1024).is_err());
    }
}
