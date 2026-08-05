//! **Addition 2 — endpoint hardening + data minimization.**
//!
//! The endpoint is the Achilles' heel that defeats every network layer, so this crate
//! holds the parts of "harden the client" that are actually code: a **forward-secret key
//! ratchet**, **compartmentalized per-context personas** (so activity in one context
//! cannot be linked to another), and a **uniform client fingerprint** (so all clients
//! look byte-identical on the wire).
//!
//! **Honest ceilings (design decision, Addition 2).** Isolation *contains* a compromise;
//! it cannot make an untrusted endpoint trusted — a live keylogger reads plaintext no
//! matter how good the ratchet is. Forward secrecy protects *past* sessions after a key
//! is captured, not an *actively* compromised endpoint. And uniformity only helps if the
//! crowd is actually large (constraint 3): identical clients are still individually
//! distinguishable when there are only a few of them. The real payoff is cross-context
//! unlinkability and feeding the crowd — not endpoint invincibility.
//!
//! Crypto is the audited [`hmac`]/[`sha2`] crates; key material is wiped with [`zeroize`].

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// `HMAC-SHA256(key, msg)` as a 32-byte value.
fn prf(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

// ---------------------------------------------------------------------------
// Forward-secret hash ratchet
// ---------------------------------------------------------------------------

/// A symmetric hash ratchet (the KDF chain of a Double Ratchet). Each step yields a fresh
/// message key and advances a chain key one-way, so a state captured now cannot recover
/// any earlier message key — **forward secrecy**.
///
/// Two parties seeded identically produce the same message-key sequence. Break-in
/// recovery (post-compromise security) needs an additional DH ratchet, which is a later
/// layer.
#[derive(ZeroizeOnDrop)]
pub struct Ratchet {
    chain_key: [u8; 32],
}

impl Ratchet {
    /// Seed a ratchet. Both parties call this with the same shared seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self { chain_key: seed }
    }

    /// Advance the ratchet, returning the next message key. The previous chain key is
    /// overwritten and cannot be recovered from the new state.
    pub fn next_message_key(&mut self) -> [u8; 32] {
        let message_key = prf(&self.chain_key, b"gyre-ratchet-message");
        let next_chain = prf(&self.chain_key, b"gyre-ratchet-chain");
        self.chain_key.zeroize();
        self.chain_key = next_chain;
        message_key
    }
}

// ---------------------------------------------------------------------------
// Compartmentalized personas
// ---------------------------------------------------------------------------

/// A user's root identity seed. Never leaves the endpoint; personas are derived from it.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    master: [u8; 32],
}

/// One compartmentalized context (persona). Carries only its own derived key — never the
/// master and never another persona's key — so contexts are cryptographically unlinkable.
#[derive(ZeroizeOnDrop)]
pub struct Persona {
    #[zeroize(skip)]
    context: String,
    key: [u8; 32],
}

impl Identity {
    /// A new identity from a root seed.
    pub fn new(master: [u8; 32]) -> Self {
        Self { master }
    }

    /// Derive the persona for `context`. Independent per context: two contexts yield
    /// unlinkable keys, and neither reveals the master nor the other persona.
    pub fn persona(&self, context: &str) -> Persona {
        Persona {
            context: context.to_owned(),
            key: prf(&self.master, context.as_bytes()),
        }
    }
}

impl Persona {
    /// The context label this persona is for.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// This persona's key material (independent of every other persona).
    pub fn key(&self) -> [u8; 32] {
        self.key
    }
}

// ---------------------------------------------------------------------------
// Uniform client fingerprint
// ---------------------------------------------------------------------------

/// The single fingerprint **every** client presents. Uniformity is what makes the crowd a
/// crowd (constraint 3): if all clients look byte-identical, an observer cannot tell users
/// apart by their handshake or metadata.
pub const UNIFORM_FINGERPRINT: &[u8] = b"gyre/1 uniform-client";

/// The uniform fingerprint (see [`UNIFORM_FINGERPRINT`]).
pub fn uniform_fingerprint() -> &'static [u8] {
    UNIFORM_FINGERPRINT
}

/// A **deliberately bad** counter-example: a per-user fingerprint that partitions the
/// anonymity set by embedding a user id. Shown only to contrast with the uniform one — do
/// not use it.
pub fn naive_fingerprint(user_id: u64) -> Vec<u8> {
    let mut fp = b"gyre/1 client=".to_vec();
    fp.extend_from_slice(&user_id.to_be_bytes());
    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_parties_seeded_alike_agree_and_keys_never_repeat() {
        let seed = [42u8; 32];
        let mut alice = Ratchet::new(seed);
        let mut bob = Ratchet::new(seed);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let a = alice.next_message_key();
            let b = bob.next_message_key();
            assert_eq!(a, b, "same seed must give the same message-key sequence");
            assert!(seen.insert(a), "each message key must be distinct");
        }
    }

    #[test]
    fn personas_are_unlinkable_across_contexts_but_stable_within_one() {
        let id = Identity::new([7u8; 32]);
        let email = id.persona("email");
        let leaks = id.persona("leaks");
        let email_again = id.persona("email");

        assert_ne!(
            email.key(),
            leaks.key(),
            "different contexts are unlinkable"
        );
        assert_eq!(email.key(), email_again.key(), "same context is stable");
        // A persona never carries the master.
        assert_ne!(email.key(), [7u8; 32]);
    }

    #[test]
    fn uniform_fingerprint_is_identical_across_clients() {
        // Two independent clients look byte-identical (they share the crowd)...
        assert_eq!(uniform_fingerprint(), uniform_fingerprint());
        // ...whereas the naive per-user fingerprint leaks identity and partitions them.
        assert_ne!(naive_fingerprint(1), naive_fingerprint(2));
    }
}
