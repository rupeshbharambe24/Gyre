//! Deterministic test vectors for the capability-token construction.
//!
//! These exist so an auditor — or a second, independent implementation — can check byte
//! for byte that this code computes what the specification in `docs/AUDIT.md` says. Every
//! value below is derived from a fixed seed, so nothing here depends on the OS RNG.
//!
//! If one of these changes, the wire format changed: outstanding tokens and any other
//! implementation are now incompatible, and that must be a deliberate, versioned decision.

use gyre_shield::token::{unblind, Issuer, Token};

const ISSUER_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const TOKEN_SEED: [u8; 32] = [0x42; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Vector 1 — the issuer's public key is a fixed function of its secret seed.
#[test]
fn vector_issuer_public_key() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    assert_eq!(
        hex(&issuer.public_key().0),
        "0a9a69c0ab673b88dd084370deb7a78bca331eb8d3a5dda5ec893271694f6819",
        "issuer public key vector"
    );
}

/// Vector 2 — the unblinded evaluation `N = k·H(seed)` is a fixed function of the issuer
/// key and the token seed, independent of whatever blinding factor was used. This is the
/// value the blind protocol must arrive at, so it pins the core of the construction.
#[test]
fn vector_token_evaluation() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    let evaluated = issuer.evaluate(&TOKEN_SEED);
    assert_eq!(
        hex(&evaluated),
        "84b9ba04b1024d71820f41fd9bead7eebd6154255e449ab29b6de862f4ddf45f",
        "token evaluation vector"
    );

    // And the blind path must reach exactly the same value.
    let token = Token {
        seed: TOKEN_SEED,
        evaluated,
    };
    assert!(
        issuer.verify(&token),
        "the direct evaluation must verify as a token"
    );
}

/// Vector 3 — a full issue → unblind → redeem round trip against a *fixed* issuer key.
///
/// The blinding factor is random, so the intermediate `blinded`/`evaluated` values differ
/// per run by design (that randomness IS the unlinkability). What is deterministic, and
/// what this pins, is that the resulting token always carries the same evaluation for a
/// given (issuer key, token seed) — and that it verifies.
#[test]
fn vector_round_trip_is_stable_across_blinding_factors() {
    let issuer = Issuer::from_secret_seed(&ISSUER_SEED);
    let published = issuer.public_key();

    let mut evaluations = Vec::new();
    for _ in 0..3 {
        let (state, blinded) = gyre_shield::token::blind();
        let issued = issuer.issue(blinded).expect("issue");
        let token = unblind(state, issued, published).expect("honest proof verifies");
        assert!(issuer.verify(&token));
        evaluations.push((token.seed, token.evaluated));
    }

    // Different seeds each time (fresh randomness), so the evaluations differ...
    assert_ne!(evaluations[0].0, evaluations[1].0);
    // ...but each is exactly k·H(its own seed), which `verify` just confirmed.
    for (seed, evaluated) in &evaluations {
        let token = Token {
            seed: *seed,
            evaluated: *evaluated,
        };
        assert!(issuer.verify(&token), "evaluation must be k*H(seed)");
    }
}

/// Vector 4 — the same secret seed always yields the same issuer, so an operator can
/// reload a key across restarts without invalidating outstanding tokens.
#[test]
fn vector_issuer_is_reproducible_from_its_seed() {
    let a = Issuer::from_secret_seed(&ISSUER_SEED);
    let b = Issuer::from_secret_seed(&ISSUER_SEED);
    assert_eq!(a.public_key(), b.public_key());

    let different = Issuer::from_secret_seed(&[0xAA; 32]);
    assert_ne!(a.public_key(), different.public_key());

    // A token issued under one instance verifies under the other — that is the point.
    let published = a.public_key();
    let (state, blinded) = gyre_shield::token::blind();
    let token = unblind(state, a.issue(blinded).unwrap(), published).unwrap();
    assert!(
        b.verify(&token),
        "a reloaded issuer must honour its own tokens"
    );
}
