//! **Addition 1 — obfuscation / pluggable transports (the "appearance" dimension).**
//!
//! This layer reshapes what the **first hop's** already-encrypted bytes *look like* on
//! the wire, so a censoring ISP cannot fingerprint-and-block the fabric by its protocol
//! signature. It sits below the link crypto and above the transport, and it only ever
//! touches already-encrypted bytes.
//!
//! **Honest ceilings (design decision, Addition 1).** This has **zero** effect on
//! anonymity, the anonymity trilemma, or a global observer — it is *blocking-resistance
//! and appearance only*. "Unblockable" is false: it is a permanent arms race, and the
//! real defense is **agility** — a swappable framework of transports — not any single
//! one. In particular, the `Polymorphic` ("looks-like-nothing") transport's uniform-
//! random output is now a *positive* fingerprint under entropy-based DPI (the Great
//! Firewall's fully-encrypted-traffic classifier, Wu et al., USENIX Security 2023). This
//! crate lets you **measure** that with [`shannon_entropy_bits_per_byte`].
//!
//! The framework is the [`Obfuscator`] trait; the transports here are illustrative
//! prototypes, not the hardened obfs4/uTLS implementations a real deployment would use.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Errors from de-obfuscating a wire stream.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed obfuscated stream")]
    Malformed,
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A pluggable transport: reshapes already-encrypted `inner` bytes into wire bytes and
/// back. The whole point of the trait is that transports are **swappable** — agility is
/// the defense, since no single disguise survives a determined censor forever.
pub trait Obfuscator {
    /// Reshape `inner` (already-encrypted) bytes into what goes on the wire.
    fn obfuscate(&self, inner: &[u8]) -> Vec<u8>;
    /// Recover the original bytes from a wire stream.
    fn deobfuscate(&self, wire: &[u8]) -> Result<Vec<u8>>;
    /// A short, stable transport name.
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Identity — the no-op baseline (raw, trivially fingerprintable).
// ---------------------------------------------------------------------------

/// Passes bytes through unchanged. The baseline a DPI box fingerprints instantly.
pub struct Identity;

impl Obfuscator for Identity {
    fn obfuscate(&self, inner: &[u8]) -> Vec<u8> {
        inner.to_vec()
    }
    fn deobfuscate(&self, wire: &[u8]) -> Result<Vec<u8>> {
        Ok(wire.to_vec())
    }
    fn name(&self) -> &'static str {
        "identity"
    }
}

// ---------------------------------------------------------------------------
// Polymorphic — obfs4-class "looks like nothing": keystream + random padding.
// ---------------------------------------------------------------------------

/// A "looks-like-nothing" transport: XORs the frame with a keyed keystream and adds a
/// random amount of padding, so each emission looks like fresh uniform-random bytes.
///
/// This demonstrates the obfs4 family *and* its modern weakness: the output is high-
/// entropy, which entropy-based DPI now flags — see the crate docs.
pub struct Polymorphic {
    key: [u8; 32],
    max_pad: usize,
}

impl Polymorphic {
    /// A transport keyed by `key` (shared with the bridge out of band).
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, max_pad: 64 }
    }
}

fn keystream(key: &[u8; 32], nonce: &[u8; 16], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(nonce);
        mac.update(&counter.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf
}

/// HMAC-SHA256 authentication tag over `data`, keyed by the transport key.
fn auth_tag(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

impl Obfuscator for Polymorphic {
    fn obfuscate(&self, inner: &[u8]) -> Vec<u8> {
        let nonce = random_bytes::<16>();
        let pad_len = (random_bytes::<1>()[0] as usize) % (self.max_pad + 1);

        // Frame: [inner_len: u32][inner][random padding], then XOR with the keystream.
        let mut frame = Vec::with_capacity(4 + inner.len() + pad_len);
        frame.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        frame.extend_from_slice(inner);
        frame.extend_from_slice(&vec_random(pad_len));

        let ks = keystream(&self.key, &nonce, frame.len());
        for (b, k) in frame.iter_mut().zip(&ks) {
            *b ^= k;
        }

        // Encrypt-then-MAC: authenticate the on-wire bytes (nonce ‖ ciphertext) so a tampered
        // frame or a wrong key is rejected deterministically, not left to a probabilistic
        // length-field check. This gives the channel integrity, not just confidentiality.
        let mut wire = Vec::with_capacity(16 + frame.len() + 32);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&frame);
        let tag = auth_tag(&self.key, &wire);
        wire.extend_from_slice(&tag);
        wire
    }

    fn deobfuscate(&self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 16 + 4 + 32 {
            return Err(Error::Malformed);
        }
        // Verify the tag over (nonce ‖ ciphertext) in constant time BEFORE trusting any field.
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        m.update(body);
        if m.verify_slice(tag).is_err() {
            return Err(Error::Malformed);
        }

        let nonce: [u8; 16] = body[0..16].try_into().unwrap();
        let xored = &body[16..];
        let ks = keystream(&self.key, &nonce, xored.len());
        let frame: Vec<u8> = xored.iter().zip(&ks).map(|(b, k)| b ^ k).collect();

        let inner_len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        if 4 + inner_len > frame.len() {
            return Err(Error::Malformed);
        }
        Ok(frame[4..4 + inner_len].to_vec())
    }

    fn name(&self) -> &'static str {
        "polymorphic"
    }
}

fn vec_random(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if n > 0 {
        getrandom::fill(&mut buf).expect("OS RNG");
    }
    buf
}

// ---------------------------------------------------------------------------
// TlsMimic — wrap in TLS-application-data record framing (blend as TLS).
// ---------------------------------------------------------------------------

const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_MAX_RECORD: usize = 16384;

/// Wraps bytes in TLS 1.2 `application_data` record framing so the stream *looks like*
/// TLS. A prototype of the "blend as a real protocol" tier.
///
/// Honest ceiling: real TLS needs a preceding handshake, the SNI is cleartext, and
/// TLS-in-TLS is detectable by packet-size/timing — this only mimics the record shape.
pub struct TlsMimic;

impl Obfuscator for TlsMimic {
    fn obfuscate(&self, inner: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        let mut push_record = |chunk: &[u8]| {
            wire.push(TLS_APPLICATION_DATA);
            wire.extend_from_slice(&TLS_VERSION);
            wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            wire.extend_from_slice(chunk);
        };
        if inner.is_empty() {
            push_record(&[]);
        } else {
            for chunk in inner.chunks(TLS_MAX_RECORD) {
                push_record(chunk);
            }
        }
        wire
    }

    fn deobfuscate(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < wire.len() {
            if i + 5 > wire.len() || wire[i] != TLS_APPLICATION_DATA {
                return Err(Error::Malformed);
            }
            let len = u16::from_be_bytes([wire[i + 3], wire[i + 4]]) as usize;
            let start = i + 5;
            let end = start + len;
            if end > wire.len() {
                return Err(Error::Malformed);
            }
            out.extend_from_slice(&wire[start..end]);
            i = end;
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        "tls-mimic"
    }
}

// ---------------------------------------------------------------------------
// Measurement + registry
// ---------------------------------------------------------------------------

/// Shannon entropy of `bytes`, in bits per byte (0..8).
///
/// High entropy (~8) is exactly what modern entropy-based DPI flags as a "looks-like-
/// nothing" tunnel — so this is how you *measure* the `Polymorphic` transport's honest
/// weakness, not just assert it.
pub fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// A default swappable set of transports (the agility that is the real defense).
pub fn default_transports(key: [u8; 32]) -> Vec<Box<dyn Obfuscator>> {
    vec![
        Box::new(Identity),
        Box::new(Polymorphic::new(key)),
        Box::new(TlsMimic),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x11; 32]
    }

    #[test]
    fn every_transport_round_trips() {
        let inputs: [&[u8]; 3] = [b"", b"a", b"the quick brown fox, already encrypted bytes"];
        for transport in default_transports(key()) {
            for input in inputs {
                let wire = transport.obfuscate(input);
                let back = transport.deobfuscate(&wire).unwrap();
                assert_eq!(
                    back,
                    input,
                    "transport {} must round-trip",
                    transport.name()
                );
            }
        }
    }

    #[test]
    fn polymorphic_is_high_entropy_and_never_repeats() {
        let poly = Polymorphic::new(key());
        let input = vec![0u8; 4096]; // low-entropy input...
        let a = poly.obfuscate(&input);
        let b = poly.obfuscate(&input);
        assert_ne!(
            a, b,
            "each emission must look different (fresh nonce + padding)"
        );
        // ...becomes high-entropy on the wire — which is exactly the DPI fingerprint.
        assert!(
            shannon_entropy_bits_per_byte(&a) > 7.0,
            "looks-like-nothing output is near-max entropy: {}",
            shannon_entropy_bits_per_byte(&a)
        );
    }

    #[test]
    fn tls_mimic_looks_like_a_tls_record() {
        let wire = TlsMimic.obfuscate(b"hello");
        assert_eq!(
            &wire[0..3],
            &[0x17, 0x03, 0x03],
            "starts with a TLS app-data header"
        );
        assert_eq!(TlsMimic.deobfuscate(&wire).unwrap(), b"hello");
    }

    #[test]
    fn entropy_meter_extremes() {
        assert_eq!(shannon_entropy_bits_per_byte(&[]), 0.0);
        assert_eq!(shannon_entropy_bits_per_byte(&[7u8; 1000]), 0.0); // one symbol
        let all_bytes: Vec<u8> = (0..=255).collect();
        assert!(shannon_entropy_bits_per_byte(&all_bytes) > 7.99); // uniform = ~8
    }
}
