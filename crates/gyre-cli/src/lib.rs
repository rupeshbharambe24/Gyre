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

use gyre_obfs::{Identity, Obfuscator, Polymorphic, TlsMimic};
use gyre_sphinx::{Relay, ADDRESS_LEN};
use sha2::{Digest, Sha256};

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
pub fn obfuscator(name: &str, cookie: &[u8]) -> Result<Box<dyn Obfuscator>, String> {
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
