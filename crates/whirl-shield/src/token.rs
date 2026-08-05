//! **Anonymous capability tokens (a blind VOPRF token).**
//!
//! Lets a client that has already paid once (e.g. solved a PoW admission puzzle)
//! obtain a token it can later redeem to *skip* the puzzle — **without the issuer being
//! able to link the redemption back to the issuance.** Unlinkability comes from
//! blinding: the issuer only ever evaluates a random *blinded* point, and never sees the
//! token itself.
//!
//! The flow (a verifiable OPRF, RFC 9497 shape):
//!
//! 1. Client: pick a random token seed, `T = H(seed)`, blind it `B = r·T` with a random
//!    scalar `r`, and send `B`.
//! 2. Issuer: return `Z = k·B` (`k` is the issuer's secret). This is the only step the
//!    issuer sees, and `B` is a uniformly random point.
//! 3. Client: unblind `N = r⁻¹·Z = k·T`. The token is `(seed, N)`.
//! 4. Redemption: send `(seed, N)`; the issuer checks `N == k·H(seed)` and that the seed
//!    is unspent. Because `r` was random and discarded, issuance and redemption are
//!    unlinkable.
//!
//! The ristretto/scalar primitives are the audited [`curve25519_dalek`] crate; the
//! *construction* here is a hand-assembled prototype and, like everything in this repo,
//! is **unaudited** — it must be reviewed before anyone relies on its unlinkability.

use std::collections::HashSet;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"whirlpool-capability-token-v1";

fn random_scalar() -> Scalar {
    let mut buf = [0u8; 64];
    getrandom::fill(&mut buf).expect("OS RNG");
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn random_seed() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf
}

/// Domain-separated hash of a seed onto the ristretto group.
fn hash_to_point(seed: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN);
    hasher.update(seed);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// The issuer's secret OPRF key, plus the set of already-redeemed seeds.
pub struct Issuer {
    key: Scalar,
    spent: HashSet<[u8; 32]>,
}

impl Issuer {
    /// A fresh issuer with a random secret key.
    pub fn new() -> Self {
        Self {
            key: random_scalar(),
            spent: HashSet::new(),
        }
    }

    /// Blind-evaluate a client's blinded point — the only value the issuer ever sees.
    /// Returns `None` if the input is not a valid point.
    pub fn issue(&self, blinded: [u8; 32]) -> Option<[u8; 32]> {
        let point = CompressedRistretto(blinded).decompress()?;
        Some((self.key * point).compress().to_bytes())
    }

    /// Check that a token is genuine: `evaluated == key · H(seed)`.
    pub fn verify(&self, token: &Token) -> bool {
        let expected = self.key * hash_to_point(&token.seed);
        match CompressedRistretto(token.evaluated).decompress() {
            Some(n) => n == expected,
            None => false,
        }
    }

    /// Redeem a token: valid **and** not previously spent. Marks it spent on success, so
    /// a second redemption of the same token fails.
    pub fn redeem(&mut self, token: &Token) -> bool {
        self.verify(token) && self.spent.insert(token.seed)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// A client's secret blinding state, kept until unblinding.
pub struct Blinding {
    seed: [u8; 32],
    blind: Scalar,
}

/// Start issuance: returns the secret state and the blinded point to send to the issuer.
pub fn blind() -> (Blinding, [u8; 32]) {
    let seed = random_seed();
    let blind = random_scalar();
    let blinded = (blind * hash_to_point(&seed)).compress().to_bytes();
    (Blinding { seed, blind }, blinded)
}

/// A finished, redeemable capability token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The token seed (revealed only at redemption).
    pub seed: [u8; 32],
    /// The unblinded evaluation `k·H(seed)`.
    pub evaluated: [u8; 32],
}

/// Unblind the issuer's response into a redeemable token. Returns `None` if the
/// response is not a valid point.
pub fn unblind(state: Blinding, issued: [u8; 32]) -> Option<Token> {
    let z = CompressedRistretto(issued).decompress()?;
    let n = state.blind.invert() * z;
    Some(Token {
        seed: state.seed,
        evaluated: n.compress().to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issued_token_verifies_and_redeems_exactly_once() {
        let mut issuer = Issuer::new();
        let (state, blinded) = blind();
        let issued = issuer.issue(blinded).unwrap();
        let token = unblind(state, issued).unwrap();

        assert!(issuer.verify(&token), "a genuine token must verify");
        assert!(issuer.redeem(&token), "first redemption succeeds");
        assert!(!issuer.redeem(&token), "double-spend is rejected");
    }

    #[test]
    fn a_forged_token_is_rejected() {
        let issuer = Issuer::new();
        // A point the issuer never signed (random·H(seed) instead of key·H(seed)).
        let (state, _blinded) = blind();
        let forged = Token {
            seed: state.seed,
            evaluated: (random_scalar() * hash_to_point(&state.seed))
                .compress()
                .to_bytes(),
        };
        assert!(
            !issuer.verify(&forged),
            "a forged evaluation must not verify"
        );
    }

    #[test]
    fn a_token_from_another_issuer_is_rejected() {
        let issuer_a = Issuer::new();
        let mut issuer_b = Issuer::new();
        let (state, blinded) = blind();
        let issued = issuer_a.issue(blinded).unwrap();
        let token = unblind(state, issued).unwrap();
        assert!(issuer_a.verify(&token));
        assert!(
            !issuer_b.redeem(&token),
            "a token is only valid at its issuer"
        );
    }

    #[test]
    fn issuance_is_unlinkable_two_blindings_look_different() {
        // The issuer's whole view is the blinded point. Blinding the same seed twice with
        // fresh random scalars yields different blinded points, so the issuer cannot tell
        // they are the same token — the basis of unlinkability.
        let seed = random_seed();
        let b1 = (random_scalar() * hash_to_point(&seed))
            .compress()
            .to_bytes();
        let b2 = (random_scalar() * hash_to_point(&seed))
            .compress()
            .to_bytes();
        assert_ne!(b1, b2);
    }
}
