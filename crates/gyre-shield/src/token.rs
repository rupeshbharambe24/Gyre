//! **Anonymous capability tokens — a blind, verifiable OPRF (RFC 9497).**
//!
//! Lets a client that has already paid once (e.g. solved a PoW admission puzzle) obtain a
//! token it can later redeem to *skip* the puzzle — **without the issuer being able to link
//! the redemption back to the issuance.** Unlinkability comes from blinding: the issuer
//! only ever evaluates a random *blinded* point and never sees the token itself.
//!
//! # This is no longer our own cryptography
//!
//! The protocol here is the [`voprf`] crate's implementation of **RFC 9497**, ciphersuite
//! `ristretto255-SHA512`. Gyre supplies the parts that are policy rather than
//! cryptography: where the issuer's public key comes from, single-use enforcement, and
//! epoch rotation.
//!
//! It did not start that way. An earlier version was hand-assembled, and reviewing it for
//! `docs/AUDIT.md` found that it was labelled a "**V**OPRF" while carrying **no DLEQ
//! proof** — the base OPRF mode. That let a malicious issuer give each client its own key
//! and, at redemption, try every key to see which verified: a **key-partitioning**
//! deanonymisation that linked *every* redemption in a proof-of-concept. Rather than keep
//! maintaining a bespoke construction, the whole thing now delegates to an audited
//! implementation of the standard — which is what design decision **D11** asked for in the
//! first place.
//!
//! # The flow
//!
//! 1. Client: pick a random 32-byte seed and [`blind`] it. The issuer sees only a
//!    uniformly random point.
//! 2. Issuer: [`Issuer::issue`] blind-evaluates it and returns the result **with a DLEQ
//!    proof** that its published key was used.
//! 3. Client: [`unblind`] verifies that proof against a **pinned** public key and only then
//!    produces the token.
//! 4. Redemption: [`Issuer::redeem`] recomputes the evaluation from the seed and checks it
//!    in constant time, plus that the seed is unspent.
//!
//! > **The public key must be pinned out of band.** Verifying a proof against a key the
//! > issuer supplied in the same response proves nothing — an attacker simply sends the
//! > matching key. [`PublicKey::from_verified_params`] takes threshold-verified consensus
//! > parameters, so a key obtained that way is provably one a quorum of authorities
//! > published.
//!
//! # What still needs review
//!
//! The *construction* is now an audited library, but this **integration** is not audited:
//! key handling, the spent set, rotation policy, and the pinning path are Gyre's code. See
//! `docs/AUDIT.md`.

use std::collections::HashSet;

use gyre_directory::VerifiedParams;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};
use zeroize::ZeroizeOnDrop;

/// The RFC 9497 ciphersuite in use: `ristretto255-SHA512`.
type Suite = Ristretto255;

/// Serialized length of a group element (blinded point, evaluation, public key).
pub const ELEMENT_LEN: usize = 32;
/// Serialized length of a DLEQ proof (two scalars).
pub const PROOF_LEN: usize = 64;
/// Length of a finalized token output (SHA-512).
pub const OUTPUT_LEN: usize = 64;
/// Length of the random token seed — the OPRF input.
pub const SEED_LEN: usize = 32;

/// Domain separator for deterministic issuer-key derivation.
const KEY_DERIVATION_INFO: &[u8] = b"gyre-capability-token-v2/issuer-key";

/// Errors from issuing or accepting a token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A supplied value is not a valid group element or proof encoding.
    #[error("malformed protocol message")]
    Malformed,
    /// **The issuer's DLEQ proof did not verify.** Either the issuer is faulty, or it used
    /// a key other than its published one — which is how a malicious issuer deanonymises
    /// clients. Refuse the token.
    #[error("the issuer's DLEQ proof did not verify: it may be using a per-client key")]
    BadProof,
    /// The underlying VOPRF implementation rejected the operation.
    #[error("voprf: {0}")]
    Voprf(String),
}

impl From<voprf::Error> for Error {
    fn from(e: voprf::Error) -> Self {
        match e {
            voprf::Error::ProofVerification => Error::BadProof,
            voprf::Error::Deserialization => Error::Malformed,
            other => Error::Voprf(other.to_string()),
        }
    }
}

/// Adapter exposing the OS CSPRNG through the `rand_core` traits `voprf` requires.
///
/// This invents no randomness: every byte comes from `getrandom`, i.e. the operating
/// system's CSPRNG. It exists only because `voprf` is generic over `RngCore + CryptoRng`.
struct OsCsprng;

/// Opaque error code reported when the OS CSPRNG fails. `rand_core::Error` requires a
/// non-zero custom code; the value itself carries no meaning beyond "getrandom failed".
const NON_ZERO_RNG_FAILURE: core::num::NonZeroU32 =
    match core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START + 1) {
        Some(v) => v,
        None => unreachable!(),
    };

impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // The infallible half of the trait has nowhere to report failure. A CSPRNG that
        // cannot produce bytes must never be papered over with predictable ones, so this
        // aborts rather than continuing with a broken source.
        getrandom::fill(dest).expect("OS CSPRNG must be available");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // The fallible half must actually be fallible — swallowing the error here would
        // make the whole `try_` API a lie to any caller that checks it.
        getrandom::fill(dest).map_err(|_| rand_core::Error::from(NON_ZERO_RNG_FAILURE))
    }
}

// SAFETY-of-claim: `getrandom` is a cryptographically secure OS RNG, which is exactly what
// this marker asserts.
impl CryptoRng for OsCsprng {}

/// Constant-time byte equality, via [`subtle`].
///
/// Token outputs are secrets: a comparison that returns early on the first differing byte
/// would let an attacker forge one byte at a time. This delegates rather than hand-rolling
/// a fold — `subtle` carries the optimisation barriers that stop a compiler from turning a
/// clever branchless expression back into a branch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}

/// The issuer's published public key.
///
/// The inner bytes are **private on purpose**. Verifying a DLEQ proof against a key the
/// issuer supplied in the same response proves nothing, so this type makes the provenance
/// of a key visible at every call site:
///
/// - [`from_verified_params`](Self::from_verified_params) — the blessed path. Takes
///   [`VerifiedParams`], which can only be produced by threshold-verifying a consensus.
/// - [`Issuer::public_key`] — an issuer's own key, for the issuer itself.
/// - [`from_unverified_bytes`](Self::from_unverified_bytes) — deliberately ugly, for tests
///   and local setups. A grep for the name finds every place trust was assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; ELEMENT_LEN]);

impl PublicKey {
    /// **The blessed path.** Take the issuer key from parameters a quorum of directory
    /// authorities signed.
    pub fn from_verified_params(params: &VerifiedParams) -> Self {
        PublicKey(params.issuer_public_key())
    }

    /// Take a key on trust, with no proof of where it came from.
    ///
    /// Named to be conspicuous. Using this with a key the issuer supplied reintroduces the
    /// key-partitioning deanonymisation attack — see the module docs and `docs/AUDIT.md`.
    pub fn from_unverified_bytes(bytes: [u8; ELEMENT_LEN]) -> Self {
        PublicKey(bytes)
    }

    /// The raw encoding, for publishing this key into a consensus document.
    pub fn to_bytes(&self) -> [u8; ELEMENT_LEN] {
        self.0
    }
}

/// What the issuer returns: the blind evaluation plus the proof it used the right key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The blind evaluation of the client's point.
    pub evaluated: [u8; ELEMENT_LEN],
    /// DLEQ proof that the published key was used.
    pub proof: [u8; PROOF_LEN],
}

/// A client's secret blinding state, kept until unblinding.
///
/// Both fields are wiped on drop. `VoprfClient` is `ZeroizeOnDrop` upstream — it holds the
/// blinding factor, whose secrecy *is* the unlinkability — and the seed is zeroized here.
/// An earlier version of this comment claimed the whole struct was wiped while the seed
/// was in fact left in memory; the code now matches the claim.
#[derive(ZeroizeOnDrop)]
pub struct Blinding {
    seed: [u8; SEED_LEN],
    /// Skipped by *this* derive because the type already wipes itself on drop.
    #[zeroize(skip)]
    client: VoprfClient<Suite>,
}

/// A finished, redeemable capability token.
///
/// Deliberately **not** `Copy`: a bearer credential that silently duplicates itself on
/// every move cannot be reliably wiped. `PartialEq` is implemented in constant time rather
/// than derived, so an ordinary `==` cannot leak the output byte-by-byte — the module
/// already compares it carefully in [`Issuer::verify`], and a derived comparison next to it
/// would be a trap.
#[derive(Clone, Debug, Eq)]
pub struct Token {
    /// The token seed — the OPRF input, revealed only at redemption.
    pub seed: [u8; SEED_LEN],
    /// The finalized OPRF output.
    pub output: [u8; OUTPUT_LEN],
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.seed, &other.seed) & constant_time_eq(&self.output, &other.output)
    }
}

/// The issuer's secret key, plus the set of redeemed seeds for this epoch.
pub struct Issuer {
    server: VoprfServer<Suite>,
    spent: HashSet<[u8; SEED_LEN]>,
}

impl Issuer {
    /// A fresh issuer with a random secret key.
    pub fn new() -> Self {
        let server = VoprfServer::<Suite>::new(&mut OsCsprng).expect("key generation");
        Self {
            server,
            spent: HashSet::new(),
        }
    }

    /// An issuer whose key is derived deterministically from a secret seed, per RFC 9497's
    /// `DeriveKeyPair`.
    ///
    /// Two real uses: an operator must be able to **reload the same key after a restart**
    /// (otherwise every restart silently invalidates outstanding tokens), and reproducible
    /// **test vectors** need it. The seed is the issuer's long-term secret.
    pub fn from_secret_seed(seed: &[u8; 32]) -> Self {
        let server = VoprfServer::<Suite>::new_from_seed(seed, KEY_DERIVATION_INFO)
            .expect("key derivation from a 32-byte seed");
        Self {
            server,
            spent: HashSet::new(),
        }
    }

    /// The public key clients verify proofs against. Publish this via the signed consensus.
    pub fn public_key(&self) -> PublicKey {
        let bytes = Suite::serialize_elem(self.server.get_public_key());
        PublicKey(fixed(&bytes).expect("ristretto255 elements are 32 bytes"))
    }

    /// Blind-evaluate a client's blinded point, returning the evaluation **and a proof**
    /// that the published key was used.
    pub fn issue(&self, blinded: [u8; ELEMENT_LEN]) -> Result<Issued, Error> {
        let element = BlindedElement::<Suite>::deserialize(&blinded)?;
        let result = self.server.blind_evaluate(&mut OsCsprng, &element);
        Ok(Issued {
            evaluated: fixed(&result.message.serialize())?,
            proof: fixed(&result.proof.serialize())?,
        })
    }

    /// The direct (non-oblivious) OPRF evaluation of `seed`.
    ///
    /// This is what [`verify`](Self::verify) compares against, exposed because generating
    /// reproducible test vectors requires it. It grants no new capability: computing it
    /// needs the secret key, so any caller already holds the issuer.
    pub fn evaluate(&self, seed: &[u8; SEED_LEN]) -> Result<[u8; OUTPUT_LEN], Error> {
        let out = self.server.evaluate(seed)?;
        fixed(&out)
    }

    /// Check that a token is genuine, in constant time.
    pub fn verify(&self, token: &Token) -> bool {
        match self.evaluate(&token.seed) {
            Ok(expected) => constant_time_eq(&expected, &token.output),
            Err(_) => false,
        }
    }

    /// Redeem a token: valid **and** not previously spent. Marks it spent on success, so a
    /// second redemption of the same token fails.
    pub fn redeem(&mut self, token: &Token) -> bool {
        self.verify(token) && self.spent.insert(token.seed)
    }

    /// How many redeemed seeds are being retained. The set grows within an epoch, so this
    /// is what [`rotate`](Self::rotate) exists to cap.
    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }

    /// Start a new epoch: generate a fresh key and forget every redeemed seed.
    ///
    /// **Required operationally, not optional.** Double-spend prevention needs the spent
    /// set, and an unbounded spent set is a memory-exhaustion DoS. Rotating bounds it by
    /// the epoch length. All outstanding tokens become invalid, so epochs must be long
    /// enough for honest clients to redeem — and the new public key must be republished.
    pub fn rotate(&mut self) {
        self.server = VoprfServer::<Suite>::new(&mut OsCsprng).expect("key generation");
        self.spent.clear();
        self.spent.shrink_to_fit();
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// Start issuance: returns the secret state and the blinded point to send to the issuer.
pub fn blind() -> (Blinding, [u8; ELEMENT_LEN]) {
    let mut seed = [0u8; SEED_LEN];
    getrandom::fill(&mut seed).expect("OS CSPRNG");
    let result =
        VoprfClient::<Suite>::blind(&seed, &mut OsCsprng).expect("blinding a 32-byte seed");
    let blinded = fixed(&result.message.serialize()).expect("ristretto255 elements are 32 bytes");
    (
        Blinding {
            seed,
            client: result.state,
        },
        blinded,
    )
}

/// Verify the issuer's proof and unblind its response into a redeemable token.
///
/// `issuer_public` **must** be a key whose provenance you can prove — normally
/// [`PublicKey::from_verified_params`]. Passing a key the issuer supplied alongside the
/// response makes the proof worthless.
pub fn unblind(state: Blinding, issued: Issued, issuer_public: PublicKey) -> Result<Token, Error> {
    let element = EvaluationElement::<Suite>::deserialize(&issued.evaluated)?;
    let proof = Proof::<Suite>::deserialize(&issued.proof)?;
    let pk = Suite::deserialize_elem(&issuer_public.0)?;

    // `finalize` performs the DLEQ verification against `pk` and fails with
    // `Error::ProofVerification` — mapped to `Error::BadProof` — if the issuer used any
    // other key. Skipping it would reintroduce the key-partitioning attack.
    let output = state.client.finalize(&state.seed, &element, &proof, pk)?;

    Ok(Token {
        seed: state.seed,
        output: fixed(&output)?,
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

    /// The wire sizes are load-bearing: they are fixed-width arrays throughout. If an
    /// upstream change moved them, this fails loudly instead of silently truncating.
    #[test]
    fn the_wire_encodings_are_the_expected_sizes() {
        let issuer = Issuer::new();
        let (state, blinded) = blind();
        assert_eq!(blinded.len(), ELEMENT_LEN);
        let issued = issuer.issue(blinded).unwrap();
        assert_eq!(issued.evaluated.len(), ELEMENT_LEN);
        assert_eq!(issued.proof.len(), PROOF_LEN);
        let token = unblind(state, issued, issuer.public_key()).unwrap();
        assert_eq!(token.output.len(), OUTPUT_LEN);
        assert_eq!(issuer.public_key().to_bytes().len(), ELEMENT_LEN);
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
        let mut forged = issue_to_client(&issuer);
        forged.output[0] ^= 0x01;
        assert!(!issuer.verify(&forged));
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

    /// **The reason the DLEQ proof exists.** An issuer evaluating with a key other than its
    /// published one is the key-partitioning deanonymisation attack; the client must refuse.
    #[test]
    fn a_response_computed_with_the_wrong_key_is_refused() {
        let honest = Issuer::new();
        let rogue = Issuer::new();
        let (state, blinded) = blind();
        let issued = rogue.issue(blinded).expect("rogue issues happily");
        assert_eq!(
            unblind(state, issued, honest.public_key()).unwrap_err(),
            Error::BadProof
        );
    }

    #[test]
    fn a_tampered_proof_is_refused() {
        let issuer = Issuer::new();
        let (state, blinded) = blind();
        let mut issued = issuer.issue(blinded).unwrap();
        issued.proof[0] ^= 0x01;
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
        let (_s1, b1) = blind();
        let (_s2, b2) = blind();
        assert_ne!(b1, b2, "each blinded point must be freshly random");
    }

    #[test]
    fn garbage_input_is_rejected_not_panicked_on() {
        let issuer = Issuer::new();
        assert!(issuer.issue([0xFFu8; ELEMENT_LEN]).is_err());
    }

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

    #[test]
    fn an_issuer_is_reproducible_from_its_seed() {
        let a = Issuer::from_secret_seed(&[9u8; 32]);
        let b = Issuer::from_secret_seed(&[9u8; 32]);
        let c = Issuer::from_secret_seed(&[8u8; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), c.public_key());
    }
}

#[cfg(test)]
mod rng_tests {
    use super::*;

    /// The RNG adapter is the one piece of new glue in this module. If it ever returned
    /// constant or low-entropy bytes, every blinding factor would collapse and
    /// unlinkability would silently disappear — so check it produces distinct output and
    /// actually fills the whole buffer.
    #[test]
    fn the_rng_adapter_produces_distinct_full_buffers() {
        let mut rng = OsCsprng;
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);

        assert_ne!(a, b, "two draws must differ");
        assert!(a.iter().any(|&x| x != 0), "must not be all zeroes");
        assert!(b.iter().any(|&x| x != 0));
        // A trailing untouched region is the classic partial-fill bug.
        assert!(
            a[48..].iter().any(|&x| x != 0),
            "the tail must be filled too"
        );
        assert_ne!(rng.next_u64(), rng.next_u64(), "next_u64 must advance");
        assert_ne!(
            rng.next_u32(),
            0u32.wrapping_sub(1),
            "next_u32 must not be a stub"
        );
    }

    /// Two independently blinded tokens must never share a blinded element — that would
    /// mean the blinding factor was reused.
    #[test]
    fn blinding_never_repeats_across_many_draws() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (_state, blinded) = blind();
            assert!(seen.insert(blinded), "a blinded element repeated");
        }
    }
}
