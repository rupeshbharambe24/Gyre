//! Deterministic test vectors for the capability token.
//!
//! These exist so an auditor — or a second implementation — can check byte for byte that
//! this code computes what `docs/AUDIT.md` says. Every value is derived from a fixed seed,
//! so nothing here depends on the OS RNG.
//!
//! If one of these changes, the wire format changed: outstanding tokens and any other
//! implementation are now incompatible, and that must be a deliberate, versioned decision.
//!
//! **These values changed once already**, when the hand-rolled construction was replaced
//! with the [`voprf`] crate's RFC 9497 implementation. That was intentional — the
//! old encoding was never deployed — and the vectors below pin the RFC-conformant one.

use gyre_shield::token::{blind, unblind, Issuer, Token, OUTPUT_LEN, SEED_LEN};

const ISSUER_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const TOKEN_SEED: [u8; SEED_LEN] = [0x42; SEED_LEN];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Vector 1 — the issuer's public key is a fixed function of its secret seed
/// (RFC 9497 `DeriveKeyPair`).
#[test]
fn vector_issuer_public_key() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    assert_eq!(
        hex(&issuer.public_key().to_bytes()),
        "fefc48110bde263d480b1e2458f0a7703ed056e97e5af8c2eae4186dc056cd55",
        "issuer public key vector"
    );
}

/// Vector 2 — the OPRF output for a fixed (issuer key, token seed) pair. This is the value
/// the blind protocol must arrive at, so it pins the core of the construction.
#[test]
fn vector_token_output() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    let output = issuer.evaluate(&TOKEN_SEED).expect("evaluate");
    assert_eq!(hex(&output), "6e01c3142b251bd1f7a675b8b3fab6b6190ce2d49b9c2b667ea48b8b02a6ee847e77822ecf796e90f636f11613586f324784618b30083d93306d447fcd5ef151", "token output vector");
    assert_eq!(output.len(), OUTPUT_LEN);

    // The direct evaluation must verify as a token.
    let token = Token {
        seed: TOKEN_SEED,
        output,
    };
    assert!(issuer.verify(&token));
}

/// Vector 3 — the blind path reaches exactly the same output the direct evaluation does,
/// whatever blinding factor was drawn. The blinding is fresh each time by design (that
/// randomness *is* the unlinkability), so it is the final output that is deterministic.
#[test]
fn vector_blind_path_matches_direct_evaluation() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    let published = issuer.public_key();

    for _ in 0..3 {
        let (state, blinded) = blind();
        let issued = issuer.issue(blinded).expect("issue");
        let token = unblind(state, issued, published).expect("honest proof verifies");

        // Same seed, computed two completely different ways.
        assert_eq!(
            issuer.evaluate(&token.seed).unwrap(),
            token.output,
            "the blind path must agree with the direct evaluation"
        );
        assert!(issuer.verify(&token));
    }
}

/// Vector 4 — the same secret seed always yields the same issuer, so an operator can
/// reload a key across restarts without invalidating outstanding tokens.
#[test]
fn vector_issuer_is_reproducible_from_its_seed() {
    let a = Issuer::from_secret_seed(&ISSUER_SEED);
    let b = Issuer::from_secret_seed(&ISSUER_SEED);
    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(
        a.evaluate(&TOKEN_SEED).unwrap(),
        b.evaluate(&TOKEN_SEED).unwrap()
    );

    let different = Issuer::from_secret_seed(&[0xAA; 32]);
    assert_ne!(a.public_key(), different.public_key());

    // A token issued under one instance verifies under the other — that is the point.
    let published = a.public_key();
    let (state, blinded) = blind();
    let token = unblind(state, a.issue(blinded).unwrap(), published).unwrap();
    assert!(
        b.verify(&token),
        "a reloaded issuer must honour its own tokens"
    );
}
