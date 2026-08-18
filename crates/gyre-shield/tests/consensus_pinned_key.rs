//! **Q4 — the key-distribution wiring that makes the DLEQ fix real.**
//!
//! The DLEQ proof only helps if the client checks it against a key it did *not* get from
//! the issuer. These tests exercise the whole chain: directory authorities sign a
//! parameters document carrying the issuer's public key, the client threshold-verifies it,
//! and only then accepts a token.
//!
//! Without this, the proof is theatre — a malicious issuer just publishes the matching key
//! alongside its response and every proof verifies.

use gyre_directory::{verify_consensus, Authority, Consensus, NetworkParams, VerifyError};
use gyre_shield::token::{
    blind, unblind, Error as TokenError, Issued, Issuer, PublicKey, ELEMENT_LEN,
};

/// Mint a token via the F14-authorized path (fetch challenge, solve, present solution).
fn authorized_issue(issuer: &mut Issuer, blinded: [u8; ELEMENT_LEN]) -> Issued {
    let now = std::time::Duration::from_secs(0);
    let challenge = issuer.issuance_challenge(now);
    let solution = challenge.solve().expect("SHA-256 supported");
    issuer
        .issue(&challenge, &solution, blinded, now)
        .expect("authorized issue")
}

/// Build a signed consensus advertising `issuer`'s key, as the authorities would.
fn signed_consensus(
    issuer_key: [u8; 32],
    epoch: u64,
    authorities: &[Authority],
    signers: usize,
) -> (Consensus, Vec<(usize, ed25519_dalek::Signature)>) {
    let params = NetworkParams {
        epoch,
        issuer_public_key: issuer_key,
        pow_difficulty_bits: 12,
        mtd_window_secs: 30,
        relays: Vec::new(),
    };
    let consensus = Consensus::new(epoch, params.encode());
    let msg = consensus.signing_bytes();
    let sigs = (0..signers)
        .map(|i| (i, authorities[i].sign(&msg)))
        .collect();
    (consensus, sigs)
}

/// The honest end-to-end flow: authorities publish the key, the client pins it, the token
/// is accepted.
#[test]
fn a_client_pins_the_issuer_key_from_the_signed_consensus() {
    let authorities: Vec<Authority> = (0..4).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();

    let mut issuer = Issuer::new();
    let (consensus, sigs) = signed_consensus(issuer.public_key().to_bytes(), 7, &authorities, 3);

    // The client does the only thing that yields a trustworthy key.
    let verified = verify_consensus(&consensus, &sigs, &keys, 3).expect("quorum signed it");
    let pinned = PublicKey::from_verified_params(&verified);

    let (state, blinded) = blind();
    let issued = authorized_issue(&mut issuer, blinded);
    let token = unblind(state, issued, pinned).expect("honest issuer, pinned key");
    assert!(issuer.redeem(&token));
}

/// **The attack, end to end.** A malicious issuer runs its own key. The client checks
/// against the *consensus* key, so the token is refused — even though the issuer's own
/// proof is internally valid.
#[test]
fn an_issuer_using_an_unpublished_key_is_refused() {
    let authorities: Vec<Authority> = (0..4).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();

    // The authorities published the honest issuer's key...
    let honest = Issuer::new();
    let (consensus, sigs) = signed_consensus(honest.public_key().to_bytes(), 7, &authorities, 3);
    let verified = verify_consensus(&consensus, &sigs, &keys, 3).unwrap();
    let pinned = PublicKey::from_verified_params(&verified);

    // ...but a different issuer answers, with a perfectly valid proof for ITS key.
    let mut rogue = Issuer::new();
    let (state, blinded) = blind();
    let issued = authorized_issue(&mut rogue, blinded);

    assert_eq!(
        unblind(state, issued, pinned).unwrap_err(),
        TokenError::BadProof,
        "a key that the authorities did not publish must be refused"
    );
}

/// A consensus that did not reach the threshold yields no key at all — there is no way to
/// obtain a `PublicKey` from it, because `VerifiedParams` cannot be constructed.
#[test]
fn a_consensus_below_threshold_yields_no_key() {
    let authorities: Vec<Authority> = (0..4).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();
    let issuer = Issuer::new();

    let (consensus, sigs) = signed_consensus(issuer.public_key().to_bytes(), 7, &authorities, 2);
    assert_eq!(
        verify_consensus(&consensus, &sigs, &keys, 3).unwrap_err(),
        VerifyError::BelowThreshold
    );
}

/// A threshold of zero must never accept an unsigned document — trust decisions fail closed.
#[test]
fn a_zero_threshold_is_refused_rather_than_accepting_anything() {
    let consensus = Consensus::new(1, b"unsigned rubbish".to_vec());
    assert_eq!(
        verify_consensus(&consensus, &[], &[], 0).unwrap_err(),
        VerifyError::ZeroThreshold
    );
}

/// A validly signed body cannot be spliced into a different epoch's envelope.
#[test]
fn a_body_from_another_epoch_is_refused() {
    let authorities: Vec<Authority> = (0..3).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();
    let issuer = Issuer::new();

    // Body says epoch 7; the envelope claims epoch 8, and the authorities sign that.
    let params = NetworkParams {
        epoch: 7,
        issuer_public_key: issuer.public_key().to_bytes(),
        pow_difficulty_bits: 12,
        mtd_window_secs: 30,
        relays: Vec::new(),
    };
    let consensus = Consensus::new(8, params.encode());
    let msg = consensus.signing_bytes();
    let sigs: Vec<_> = (0..3).map(|i| (i, authorities[i].sign(&msg))).collect();

    assert_eq!(
        verify_consensus(&consensus, &sigs, &keys, 2).unwrap_err(),
        VerifyError::EpochMismatch {
            body: 7,
            consensus: 8
        }
    );
}
