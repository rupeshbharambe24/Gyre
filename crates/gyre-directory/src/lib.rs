//! **Addition 4 — decentralization + attestation (the trust-locus row).**
//!
//! Moves trust from "a few operators you must trust" to "many parties whose cheating is
//! publicly *detectable*." Concretely:
//!
//! - A directory **consensus** (the relay set + params both rotors read) is accepted only
//!   if at least `t` of `n` directory authorities signed it, so no single — or any group
//!   smaller than `t` — of authorities can forge one.
//! - If two *different* consensus bodies for the *same* epoch are each validly
//!   threshold-signed, that is cryptographic **proof of equivocation** (a
//!   Certificate-Transparency-style equivocation check).
//! - A relay's **build hash** is "blessed" only when at least `t` independent rebuilders
//!   each signed the same hash (reproducible-build attestation).
//!
//! **Honest ceilings (Addition 4).** This is **detection, not prevention** — a
//! transparency check proves a malicious ≥`t` majority cheated *after the fact*; it cannot
//! stop them signing a bad document in real time. Reproducible builds prove *binary ==
//! source* and that many parties got the same binary — **not** that a running relay
//! actually loaded it (no runtime binding without a TEE, and TEEs are breakable). The
//! threshold here is a `t`-of-`n` **ed25519 multisig**; production would use threshold-BLS
//! for compactness. All of this is control-plane hardening: **zero** effect on the
//! anonymity trilemma or a global observer.
//!
//! Signatures are the audited [`ed25519_dalek`] crate (D11).

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub mod params;
pub use params::{NetworkParams, ParamsError, RelayDescriptor, PARAMS_VERSION};

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG");
    bytes
}

/// A directory authority — or an independent rebuilder — identified by an ed25519 keypair.
pub struct Authority {
    signing: SigningKey,
}

impl Authority {
    /// Generate a fresh authority with a random key.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::from_bytes(&random_32()),
        }
    }

    /// This authority's public verifying key (published in the authority list).
    pub fn public(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign a message (a consensus document or a build hash).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

/// Count the number of **distinct** known authorities that validly signed `msg`. A
/// signature whose claimed index is unknown, or that fails verification, is ignored.
fn distinct_valid_signers(
    msg: &[u8],
    sigs: &[(usize, Signature)],
    authorities: &[VerifyingKey],
) -> usize {
    let mut valid = HashSet::new();
    for (idx, sig) in sigs {
        if let Some(vk) = authorities.get(*idx) {
            if vk.verify(msg, sig).is_ok() {
                valid.insert(*idx);
            }
        }
    }
    valid.len()
}

/// A directory consensus: an epoch plus the canonical bytes both rotors consume (relay
/// set, per-relay keys, MTD parameters, PoW difficulty). `body` is opaque here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consensus {
    /// The consensus epoch (e.g. hourly counter).
    pub epoch: u64,
    /// The canonical, opaque consensus body.
    pub body: Vec<u8>,
}

impl Consensus {
    /// A consensus for `epoch` carrying `body`.
    pub fn new(epoch: u64, body: Vec<u8>) -> Self {
        Self { epoch, body }
    }

    /// The exact bytes authorities sign.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + self.body.len());
        msg.extend_from_slice(&self.epoch.to_be_bytes());
        msg.extend_from_slice(&self.body);
        msg
    }
}

/// Accept a consensus only if at least `threshold` distinct authorities signed it.
///
/// **A `threshold` of zero is rejected**, not treated as "no signatures required". A caller
/// that derives its threshold from configuration can easily compute `0` — from an empty
/// authority list, say — and a naive `count >= 0` would then accept a completely unsigned
/// document. Trust decisions fail closed.
pub fn accept_consensus(
    consensus: &Consensus,
    sigs: &[(usize, Signature)],
    authorities: &[VerifyingKey],
    threshold: usize,
) -> bool {
    if threshold == 0 {
        return false;
    }
    distinct_valid_signers(&consensus.signing_bytes(), sigs, authorities) >= threshold
}

/// Network parameters that have been **threshold-verified**.
///
/// This type is the whole point: it can only be produced by [`verify_consensus`], so a
/// value of this type is proof that a quorum of authorities signed these parameters. Code
/// that requires pinned values takes a `&VerifiedParams` and therefore cannot be handed
/// unverified ones by accident.
#[derive(Clone, Debug)]
pub struct VerifiedParams {
    params: NetworkParams,
}

impl VerifiedParams {
    /// The verified parameters.
    pub fn params(&self) -> &NetworkParams {
        &self.params
    }

    /// The capability-token issuer's public key, as published by the authorities.
    ///
    /// This is the value a client must pin when checking an issuer's DLEQ proof.
    pub fn issuer_public_key(&self) -> [u8; 32] {
        self.params.issuer_public_key
    }

    /// The epoch these parameters describe.
    pub fn epoch(&self) -> u64 {
        self.params.epoch
    }
}

/// Errors from verifying a consensus document.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// A threshold of zero would accept anything; refused.
    #[error("a threshold of zero would accept an unsigned document")]
    ZeroThreshold,
    /// Fewer than `threshold` distinct authorities produced a valid signature.
    #[error("not enough distinct valid signatures to meet the threshold")]
    BelowThreshold,
    /// The signed body is not a well-formed parameters document.
    #[error("consensus body: {0}")]
    Body(#[from] ParamsError),
    /// The body's epoch disagrees with the consensus that carries it.
    #[error("body is for epoch {body} but the consensus is for epoch {consensus}")]
    EpochMismatch { body: u64, consensus: u64 },
}

/// Verify a consensus and return its parameters — **the only way to obtain
/// [`VerifiedParams`]**.
///
/// Checks, in order: a non-zero threshold, enough distinct valid signatures, a well-formed
/// body, and that the body's epoch matches the consensus carrying it (so a validly signed
/// body cannot be spliced into a different epoch's envelope).
pub fn verify_consensus(
    consensus: &Consensus,
    sigs: &[(usize, Signature)],
    authorities: &[VerifyingKey],
    threshold: usize,
) -> Result<VerifiedParams, VerifyError> {
    if threshold == 0 {
        return Err(VerifyError::ZeroThreshold);
    }
    if !accept_consensus(consensus, sigs, authorities, threshold) {
        return Err(VerifyError::BelowThreshold);
    }
    let params = NetworkParams::decode(&consensus.body)?;
    if params.epoch != consensus.epoch {
        return Err(VerifyError::EpochMismatch {
            body: params.epoch,
            consensus: consensus.epoch,
        });
    }
    Ok(VerifiedParams { params })
}

/// Detect equivocation: two *different* consensus bodies for the *same* epoch, each
/// validly threshold-signed, is proof the authorities cheated.
pub fn detect_equivocation(
    a: &Consensus,
    sigs_a: &[(usize, Signature)],
    b: &Consensus,
    sigs_b: &[(usize, Signature)],
    authorities: &[VerifyingKey],
    threshold: usize,
) -> bool {
    a.epoch == b.epoch
        && a.body != b.body
        && accept_consensus(a, sigs_a, authorities, threshold)
        && accept_consensus(b, sigs_b, authorities, threshold)
}

/// A relay build hash is "blessed" only when at least `threshold` independent rebuilders
/// each signed the same hash.
///
/// Like [`accept_consensus`], this **fails closed on a zero threshold**. Without the guard
/// the comparison is `count >= 0`, which is true for the empty signature set — so an
/// unknown hash nobody signed would be reported as blessed. Attestation is the weaker of
/// the two trust mechanisms anyway (it proves `binary == source`, never what a relay is
/// actually running), and a fail-open version of it is worth strictly less than nothing:
/// it would report agreement that no rebuilder ever expressed.
pub fn build_is_blessed(
    hash: &[u8; 32],
    sigs: &[(usize, Signature)],
    rebuilders: &[VerifyingKey],
    threshold: usize,
) -> bool {
    if threshold == 0 {
        return false;
    }
    distinct_valid_signers(hash, sigs, rebuilders) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quorum(n: usize) -> (Vec<Authority>, Vec<VerifyingKey>) {
        let authorities: Vec<Authority> = (0..n).map(|_| Authority::generate()).collect();
        let keys = authorities.iter().map(Authority::public).collect();
        (authorities, keys)
    }

    fn signed_by(authorities: &[Authority], who: &[usize], msg: &[u8]) -> Vec<(usize, Signature)> {
        who.iter().map(|&i| (i, authorities[i].sign(msg))).collect()
    }

    #[test]
    fn a_consensus_needs_t_of_n_signatures() {
        let (authorities, keys) = quorum(5);
        let consensus = Consensus::new(42, b"relay-set-v1".to_vec());
        let msg = consensus.signing_bytes();

        let three = signed_by(&authorities, &[0, 1, 2], &msg);
        assert!(
            accept_consensus(&consensus, &three, &keys, 3),
            "3-of-5 accepted"
        );

        let two = signed_by(&authorities, &[0, 4], &msg);
        assert!(
            !accept_consensus(&consensus, &two, &keys, 3),
            "2-of-5 rejected"
        );

        let one = signed_by(&authorities, &[1], &msg);
        assert!(
            !accept_consensus(&consensus, &one, &keys, 3),
            "no single authority can forge"
        );
    }

    #[test]
    fn a_tampered_body_invalidates_the_signatures() {
        let (authorities, keys) = quorum(5);
        let real = Consensus::new(42, b"relay-set-v1".to_vec());
        let sigs = signed_by(&authorities, &[0, 1, 2], &real.signing_bytes());
        let tampered = Consensus::new(42, b"relay-set-EVIL".to_vec());
        assert!(
            !accept_consensus(&tampered, &sigs, &keys, 3),
            "signatures do not cover the new body"
        );
    }

    #[test]
    fn a_signature_from_a_stranger_does_not_count() {
        let (authorities, keys) = quorum(3);
        let consensus = Consensus::new(1, b"x".to_vec());
        let msg = consensus.signing_bytes();
        let stranger = Authority::generate();
        // The stranger signs but claims authority index 0.
        let sigs = vec![
            (0usize, stranger.sign(&msg)),
            (1usize, authorities[1].sign(&msg)),
        ];
        // Only index 1 is genuine, so this is 1 valid signer, not 2.
        assert!(!accept_consensus(&consensus, &sigs, &keys, 2));
    }

    #[test]
    fn equivocation_is_detected() {
        let (authorities, keys) = quorum(5);
        let a = Consensus::new(7, b"good".to_vec());
        let b = Consensus::new(7, b"evil".to_vec());
        let sa = signed_by(&authorities, &[0, 1, 2], &a.signing_bytes());
        let sb = signed_by(&authorities, &[2, 3, 4], &b.signing_bytes());
        assert!(
            detect_equivocation(&a, &sa, &b, &sb, &keys, 3),
            "two signed bodies, one epoch"
        );

        // The same body twice is not equivocation.
        let sa2 = signed_by(&authorities, &[0, 1, 2], &a.signing_bytes());
        assert!(!detect_equivocation(&a, &sa, &a, &sa2, &keys, 3));
    }

    #[test]
    fn a_build_is_blessed_only_by_enough_rebuilders() {
        let (rebuilders, keys) = quorum(4);
        let hash = [0xABu8; 32];
        let three = signed_by(&rebuilders, &[0, 1, 2], &hash);
        assert!(
            build_is_blessed(&hash, &three, &keys, 3),
            "3 rebuilders bless it"
        );

        let two = signed_by(&rebuilders, &[0, 1], &hash);
        assert!(!build_is_blessed(&hash, &two, &keys, 3), "2 is not enough");

        // Signatures over the blessed hash do not bless a different hash.
        let other = [0xCDu8; 32];
        assert!(!build_is_blessed(&other, &three, &keys, 3));
    }
}
