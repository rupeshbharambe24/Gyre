//! **Anonymous capability tokens — a blind, *verifiable* OPRF token.**
//!
//! Lets a client that has already paid once (e.g. solved a PoW admission puzzle) obtain a
//! token it can later redeem to *skip* the puzzle — **without the issuer being able to link
//! the redemption back to the issuance.** Unlinkability comes from blinding: the issuer only
//! ever evaluates a random *blinded* point and never sees the token itself.
//!
//! The flow (a verifiable OPRF, RFC 9497 *shape* — see the deviations below):
//!
//! 1. Client: pick a random token seed, `T = H(seed)`, blind it `B = r·T` with a random
//!    scalar `r`, and send `B`.
//! 2. Issuer: return `Z = k·B` (`k` is the issuer's secret) **together with a DLEQ proof**
//!    that the same `k` behind its published public key `Y = k·G` was used. `B` is a
//!    uniformly random point, so this is all the issuer ever sees.
//! 3. Client: **verify the proof against the published `Y`**, then unblind
//!    `N = r⁻¹·Z = k·T`. The token is `(seed, N)`.
//! 4. Redemption: send `(seed, N)`; the issuer checks `N == k·H(seed)` and that the seed is
//!    unspent. Because `r` was random and discarded, issuance and redemption are unlinkable.
//!
//! # Why the proof is load-bearing
//!
//! Without step 2's proof this is the *base* OPRF mode, and a malicious issuer breaks
//! unlinkability completely with **key partitioning**: give each client its own key `kᵢ`,
//! then at redemption try every key and see which one verifies. That identifies the exact
//! issuance session. This is not theoretical — the attack is reproduced against the
//! unprotected construction in `tests/token_unlinkability.rs`, where it linked **every**
//! redemption. The DLEQ proof is what makes it detectable at issuance time.
//!
//! > **The public key must be pinned out of band.** Verifying a proof against a key the
//! > issuer supplied in the same response proves nothing — the attacker simply sends the
//! > matching key. `Y` must come from the threshold-signed directory consensus
//! > (`gyre-directory`), so that every client checks against the *same* key.
//!
//! # Status — still unaudited
//!
//! The ristretto/scalar primitives are the audited [`curve25519_dalek`] crate, but this
//! *construction* is hand-assembled and **has not been reviewed by a cryptographer**. It
//! deviates from RFC 9497 in ways that matter for interoperability and for inheriting the
//! RFC's analysis — see `docs/AUDIT.md` for the full list, the security model, and test
//! vectors.

use std::collections::HashSet;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use gyre_directory::VerifiedParams;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for hashing a seed onto the group.
const DST_HASH_TO_GROUP: &[u8] = b"gyre-capability-token-v1/hash-to-group";
/// Domain separator for the DLEQ proof transcript. Distinct from the one above so a hash
/// computed for one purpose can never be reinterpreted as the other.
const DST_DLEQ: &[u8] = b"gyre-capability-token-v1/dleq";

/// Errors from issuing or accepting a token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A supplied 32-byte value is not a canonical ristretto point.
    #[error("not a canonical ristretto point")]
    InvalidPoint,
    /// A supplied 32-byte value is not a canonical scalar.
    #[error("not a canonical scalar")]
    InvalidScalar,
    /// **The issuer's DLEQ proof did not verify.** Either the issuer is faulty, or it used a
    /// key other than its published one — which is how a malicious issuer deanonymises
    /// clients. Refuse the token.
    #[error("the issuer's DLEQ proof did not verify: it may be using a per-client key")]
    BadProof,
}

fn random_scalar() -> Scalar {
    let mut buf = [0u8; 64];
    getrandom::fill(&mut buf).expect("OS RNG");
    let s = Scalar::from_bytes_mod_order_wide(&buf);
    buf.zeroize();
    s
}

fn random_seed() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG");
    buf
}

fn decompress(bytes: &[u8; 32]) -> Result<RistrettoPoint, Error> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or(Error::InvalidPoint)
}

fn scalar_from(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::InvalidScalar)
}

/// Domain-separated hash of a seed onto the ristretto group.
///
/// The seed is a fixed 32 bytes *by type*, so `DST ‖ seed` cannot be parsed two ways —
/// there is no need for a length prefix and no room for a canonicalisation ambiguity.
fn hash_to_point(seed: &[u8; 32]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(DST_HASH_TO_GROUP);
    hasher.update(seed);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    let p = RistrettoPoint::from_uniform_bytes(&wide);
    wide.zeroize();
    p
}

/// A non-interactive proof that `log_G(Y) == log_B(Z)` — i.e. that the issuer evaluated the
/// client's point with the *same* secret key as the one behind its published public key.
///
/// Chaum–Pedersen, made non-interactive with Fiat–Shamir over a domain-separated
/// transcript of every public value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DleqProof {
    /// The Fiat–Shamir challenge.
    pub c: [u8; 32],
    /// The prover's response.
    pub s: [u8; 32],
}

/// The challenge binds every public value in the transcript. All six elements are
/// compressed ristretto points of exactly 32 bytes, so the concatenation is unambiguous.
fn dleq_challenge(
    y: &RistrettoPoint,
    b: &RistrettoPoint,
    z: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DST_DLEQ);
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    hasher.update(y.compress().as_bytes());
    hasher.update(b.compress().as_bytes());
    hasher.update(z.compress().as_bytes());
    hasher.update(a1.compress().as_bytes());
    hasher.update(a2.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn dleq_prove(k: &Scalar, y: &RistrettoPoint, b: &RistrettoPoint, z: &RistrettoPoint) -> DleqProof {
    let mut r = random_scalar();
    let a1 = RISTRETTO_BASEPOINT_POINT * r;
    let a2 = b * r;
    let c = dleq_challenge(y, b, z, &a1, &a2);
    let s = r + c * k;
    r.zeroize();
    DleqProof {
        c: c.to_bytes(),
        s: s.to_bytes(),
    }
}

fn dleq_verify(
    proof: &DleqProof,
    y: &RistrettoPoint,
    b: &RistrettoPoint,
    z: &RistrettoPoint,
) -> Result<(), Error> {
    let c = scalar_from(&proof.c)?;
    let s = scalar_from(&proof.s)?;
    // A1 = s·G − c·Y and A2 = s·B − c·Z reconstruct the prover's commitments iff the
    // same k underlies both Y and Z.
    let a1 = RISTRETTO_BASEPOINT_POINT * s - y * c;
    let a2 = b * s - z * c;
    if dleq_challenge(y, b, z, &a1, &a2) == c {
        Ok(())
    } else {
        Err(Error::BadProof)
    }
}

/// The issuer's published public key, `Y = k·G`.
///
/// The inner bytes are **private on purpose**. Verifying a DLEQ proof against a key the
/// issuer supplied in the same response proves nothing, so the type is built to make the
/// provenance of a key visible at every call site:
///
/// - [`from_verified_params`](Self::from_verified_params) — the blessed path. Takes
///   [`VerifiedParams`], which can only be produced by threshold-verifying a consensus, so
///   a key obtained this way is *provably* one a quorum of authorities published.
/// - [`Issuer::public_key`] — an issuer's own key, for the issuer itself.
/// - [`from_unverified_bytes`](Self::from_unverified_bytes) — deliberately ugly, for tests
///   and local setups. A grep for the name finds every place trust was assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// **The blessed path.** Take the issuer key from parameters a quorum of directory
    /// authorities signed.
    ///
    /// Because [`VerifiedParams`] cannot be constructed without passing threshold
    /// verification, holding one is proof the key was published by the authorities rather
    /// than chosen by whoever is on the other end of the connection.
    pub fn from_verified_params(params: &VerifiedParams) -> Self {
        PublicKey(params.issuer_public_key())
    }

    /// Take a key on trust, with no proof of where it came from.
    ///
    /// Named to be conspicuous. Using this with a key the issuer supplied reintroduces the
    /// key-partitioning deanonymisation attack the DLEQ proof exists to prevent — see the
    /// module docs and `docs/AUDIT.md`.
    pub fn from_unverified_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    /// The raw encoding, for publishing this key into a consensus document.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// What the issuer returns: the blind evaluation plus the proof it used the right key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    /// `Z = k·B`.
    pub evaluated: [u8; 32],
    /// Proof that `Z` was computed with the key behind the published public key.
    pub proof: DleqProof,
}

/// The issuer's secret OPRF key, its published public key, and the set of redeemed seeds.
#[derive(ZeroizeOnDrop)]
pub struct Issuer {
    key: Scalar,
    #[zeroize(skip)]
    public: RistrettoPoint,
    #[zeroize(skip)]
    spent: HashSet<[u8; 32]>,
}

impl Issuer {
    /// A fresh issuer with a random secret key.
    pub fn new() -> Self {
        let key = random_scalar();
        Self {
            public: RISTRETTO_BASEPOINT_POINT * key,
            key,
            spent: HashSet::new(),
        }
    }

    /// An issuer whose key is derived deterministically from 32 bytes of secret seed.
    ///
    /// Two uses, both real: an operator must be able to **reload the same key after a
    /// restart** (otherwise every restart silently invalidates outstanding tokens), and an
    /// auditor needs reproducible **test vectors**. The seed is expanded through SHA-512 and
    /// reduced, so any 32 bytes give a uniformly distributed scalar.
    ///
    /// The seed is the issuer's long-term secret — treat it exactly as such.
    pub fn from_secret_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"gyre-capability-token-v1/issuer-key");
        hasher.update(seed);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hasher.finalize());
        let key = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        Self {
            public: RISTRETTO_BASEPOINT_POINT * key,
            key,
            spent: HashSet::new(),
        }
    }

    /// The public key clients verify proofs against. Publish this via the signed consensus.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.public.compress().to_bytes())
    }

    /// Blind-evaluate a client's blinded point, returning the evaluation **and a proof**
    /// that the published key was used. The blinded point is the only value the issuer sees.
    pub fn issue(&self, blinded: [u8; 32]) -> Result<Issued, Error> {
        let b = decompress(&blinded)?;
        let z = b * self.key;
        Ok(Issued {
            evaluated: z.compress().to_bytes(),
            proof: dleq_prove(&self.key, &self.public, &b, &z),
        })
    }

    /// The unblinded OPRF evaluation `k·H(seed)` — RFC 9497's *direct* (non-oblivious)
    /// evaluation.
    ///
    /// This is what [`verify`](Self::verify) compares against, exposed because generating
    /// reproducible test vectors requires it. It grants no new capability: computing it
    /// needs the secret key, so anyone who can call it already holds the issuer.
    pub fn evaluate(&self, seed: &[u8; 32]) -> [u8; 32] {
        (hash_to_point(seed) * self.key).compress().to_bytes()
    }

    /// Check that a token is genuine: `evaluated == key · H(seed)`.
    pub fn verify(&self, token: &Token) -> bool {
        match decompress(&token.evaluated) {
            Ok(n) => n == hash_to_point(&token.seed) * self.key,
            Err(_) => false,
        }
    }

    /// Redeem a token: valid **and** not previously spent. Marks it spent on success, so a
    /// second redemption of the same token fails.
    pub fn redeem(&mut self, token: &Token) -> bool {
        self.verify(token) && self.spent.insert(token.seed)
    }

    /// How many redeemed seeds are being retained. The set grows without bound within an
    /// epoch, so this is what [`rotate`](Self::rotate) exists to cap.
    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }

    /// Start a new epoch: generate a fresh key and forget every redeemed seed.
    ///
    /// **This is required operationally, not optional.** Double-spend prevention needs the
    /// spent set, and an unbounded spent set is a memory-exhaustion DoS: an attacker who
    /// obtains many tokens can grow it indefinitely. Rotating bounds it by the epoch length.
    /// All outstanding tokens from the previous epoch become invalid, so epochs must be long
    /// enough for honest clients to redeem — and the new public key must be republished.
    pub fn rotate(&mut self) {
        self.key.zeroize();
        self.key = random_scalar();
        self.public = RISTRETTO_BASEPOINT_POINT * self.key;
        self.spent.clear();
        self.spent.shrink_to_fit();
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// A client's secret blinding state, kept until unblinding.
///
/// The blinding scalar is what makes issuance and redemption unlinkable; it is wiped on
/// drop so it cannot be recovered from memory afterwards.
#[derive(ZeroizeOnDrop)]
pub struct Blinding {
    seed: [u8; 32],
    blind: Scalar,
}

/// Start issuance: returns the secret state and the blinded point to send to the issuer.
pub fn blind() -> (Blinding, [u8; 32]) {
    let seed = random_seed();
    let blind = random_scalar();
    let blinded = (hash_to_point(&seed) * blind).compress().to_bytes();
    (Blinding { seed, blind }, blinded)
}

/// A finished, redeemable capability token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    /// The token seed (revealed only at redemption).
    pub seed: [u8; 32],
    /// The unblinded evaluation `k·H(seed)`.
    pub evaluated: [u8; 32],
}

/// Verify the issuer's proof and unblind its response into a redeemable token.
///
/// `issuer_public` **must** be the key from the signed directory consensus. Passing a key
/// the issuer supplied alongside the response makes the proof worthless.
pub fn unblind(state: Blinding, issued: Issued, issuer_public: PublicKey) -> Result<Token, Error> {
    let y = decompress(&issuer_public.to_bytes())?;
    let z = decompress(&issued.evaluated)?;
    let b = hash_to_point(&state.seed) * state.blind;

    // Refuse the token unless the issuer proved it used its published key. Skipping this
    // check reintroduces the key-partitioning deanonymisation attack.
    dleq_verify(&issued.proof, &y, &b, &z)?;

    let n = z * state.blind.invert();
    Ok(Token {
        seed: state.seed,
        evaluated: n.compress().to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_to_client(issuer: &Issuer) -> Token {
        let (state, blinded) = blind();
        let issued = issuer.issue(blinded).expect("issue");
        unblind(state, issued, issuer.public_key()).expect("unblind")
    }

    #[test]
    fn an_issued_token_verifies_and_redeems_exactly_once() {
        let mut issuer = Issuer::new();
        let token = issue_to_client(&issuer);

        assert!(issuer.verify(&token), "a genuine token must verify");
        assert!(issuer.redeem(&token), "first redemption succeeds");
        assert!(!issuer.redeem(&token), "double-spend is rejected");
    }

    #[test]
    fn a_forged_token_is_rejected() {
        let issuer = Issuer::new();
        let (state, _blinded) = blind();
        let forged = Token {
            seed: state.seed,
            evaluated: (hash_to_point(&state.seed) * random_scalar())
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
        let token = issue_to_client(&issuer_a);
        assert!(issuer_a.verify(&token));
        assert!(
            !issuer_b.redeem(&token),
            "a token is only valid at its issuer"
        );
    }

    /// **The reason the DLEQ proof exists.** An issuer that evaluates with a key other than
    /// its published one is exactly the key-partitioning deanonymisation attack, and the
    /// client must refuse the token rather than carry a tracking tag.
    #[test]
    fn a_response_computed_with_the_wrong_key_is_refused() {
        let honest = Issuer::new();
        let (state, blinded) = blind();

        // A malicious issuer evaluates with a per-client key while publishing another.
        let rogue_key = random_scalar();
        let b = decompress(&blinded).unwrap();
        let z = b * rogue_key;
        let forged = Issued {
            evaluated: z.compress().to_bytes(),
            // Proof made with the rogue key — it cannot match the published Y.
            proof: dleq_prove(&rogue_key, &(RISTRETTO_BASEPOINT_POINT * rogue_key), &b, &z),
        };

        assert_eq!(
            unblind(state, forged, honest.public_key()).unwrap_err(),
            Error::BadProof,
            "a client must refuse a token it cannot prove was honestly issued"
        );
    }

    #[test]
    fn a_tampered_proof_is_refused() {
        let issuer = Issuer::new();
        let (state, blinded) = blind();
        let mut issued = issuer.issue(blinded).unwrap();
        issued.proof.s[0] ^= 0x01;
        assert!(unblind(state, issued, issuer.public_key()).is_err());
    }

    #[test]
    fn a_proof_for_a_different_public_key_is_refused() {
        let issuer = Issuer::new();
        let other = Issuer::new();
        let (state, blinded) = blind();
        let issued = issuer.issue(blinded).unwrap();
        assert_eq!(
            unblind(state, issued, other.public_key()).unwrap_err(),
            Error::BadProof
        );
    }

    #[test]
    fn issuance_is_unlinkable_two_blindings_look_different() {
        // The issuer's whole view is the blinded point. Blinding the same seed twice with
        // fresh random scalars yields different blinded points, so the issuer cannot tell
        // they are the same token — the basis of unlinkability.
        let seed = random_seed();
        let b1 = (hash_to_point(&seed) * random_scalar())
            .compress()
            .to_bytes();
        let b2 = (hash_to_point(&seed) * random_scalar())
            .compress()
            .to_bytes();
        assert_ne!(b1, b2);
    }

    #[test]
    fn garbage_input_is_rejected_not_panicked_on() {
        let issuer = Issuer::new();
        // 0xFF.. is not a canonical ristretto encoding.
        assert_eq!(issuer.issue([0xFFu8; 32]).unwrap_err(), Error::InvalidPoint);
    }

    /// Rotation is what bounds the spent set, and it must invalidate the old epoch's tokens.
    #[test]
    fn rotation_bounds_the_spent_set_and_invalidates_old_tokens() {
        let mut issuer = Issuer::new();
        let old_public = issuer.public_key();
        let token = issue_to_client(&issuer);
        assert!(issuer.redeem(&token));
        assert_eq!(issuer.spent_count(), 1);

        issuer.rotate();
        assert_eq!(issuer.spent_count(), 0, "rotation must clear the spent set");
        assert_ne!(
            issuer.public_key(),
            old_public,
            "rotation must change the key"
        );
        assert!(
            !issuer.verify(&token),
            "a token from the previous epoch must no longer verify"
        );
    }
}
