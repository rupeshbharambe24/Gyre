//! Regression tests for the capability token's **unlinkability**, the one property it
//! exists to provide.
//!
//! ## The vulnerability these pin down
//!
//! The construction was originally documented as a "blind VOPRF (RFC 9497 shape)" but
//! carried **no DLEQ proof** — it was the *base* OPRF mode. That gap enables a standard
//! **key-partitioning** deanonymisation attack:
//!
//! 1. A malicious issuer gives each client its own secret key `kᵢ` instead of one shared
//!    key, publishing whichever key it likes (nobody could check).
//! 2. The client had no way to verify which key was used, so it accepted the response.
//! 3. At redemption the issuer tries every key it handed out. Exactly one verifies —
//!    identifying the precise issuance session, and with it the client.
//!
//! A proof-of-concept against the unprotected construction linked **5 of 5** redemptions.
//! The fix is the DLEQ proof: the issuer must prove it used the key behind its *published*
//! public key, and `unblind` refuses the token otherwise.

use gyre_shield::token::{blind, unblind, Error, Issuer};

/// **The attack, run against the fixed construction.** A malicious issuer evaluates with a
/// key other than the one clients pinned. Every client must refuse, so nothing links.
#[test]
fn a_key_partitioning_issuer_cannot_tag_any_client() {
    // What every client pinned out of band (in production: the signed consensus).
    let honest = Issuer::new();
    let published = honest.public_key();

    // The malicious issuer runs a separate key per client and proves against *its own*
    // key — a perfectly valid proof, just not for the key clients actually trust.
    let clients = 5;
    let mut accepted = 0;
    for _ in 0..clients {
        let rogue = Issuer::new();
        let (state, blinded) = blind();
        let issued = rogue.issue(blinded).expect("rogue issues happily");

        match unblind(state, issued, published) {
            Ok(_) => accepted += 1,
            Err(e) => assert_eq!(
                e,
                Error::BadProof,
                "must fail on the proof, not by accident"
            ),
        }
    }

    assert_eq!(
        accepted, 0,
        "every client must refuse a token issued under an unpublished key; \
         {accepted} of {clients} were tagged"
    );
}

/// The honest path still works — the check is not simply refusing everything.
#[test]
fn an_honest_issuer_is_still_accepted_and_redeemable() {
    let mut issuer = Issuer::new();
    let published = issuer.public_key();

    let (state, blinded) = blind();
    let issued = issuer.issue(blinded).expect("issue");
    let token = unblind(state, issued, published).expect("an honest proof must verify");

    assert!(
        issuer.redeem(&token),
        "an honestly issued token must redeem"
    );
    assert!(!issuer.redeem(&token), "and only once");
}

/// The issuer's view of two issuances is two uniformly random points, so it holds nothing
/// that distinguishes them. This is the positive statement of unlinkability.
#[test]
fn the_issuer_sees_nothing_that_distinguishes_two_issuances() {
    let issuer = Issuer::new();
    let published = issuer.public_key();

    let (s1, b1) = blind();
    let (s2, b2) = blind();
    assert_ne!(b1, b2, "two blinded points must differ");

    let t1 = unblind(s1, issuer.issue(b1).unwrap(), published).unwrap();
    let t2 = unblind(s2, issuer.issue(b2).unwrap(), published).unwrap();

    // Nothing the issuer saw at issuance (b1, b2) appears in what it sees at redemption.
    assert_ne!(t1.seed, t2.seed);
    for token in [&t1, &t2] {
        assert_ne!(
            token.evaluated, b1,
            "the token must not echo a blinded point"
        );
        assert_ne!(token.evaluated, b2);
        assert_ne!(token.seed, b1);
        assert_ne!(token.seed, b2);
    }
}

/// Rotation must genuinely invalidate the previous epoch, or the spent set could not be
/// cleared safely and double-spend prevention would silently regress.
#[test]
fn rotating_the_epoch_invalidates_outstanding_tokens() {
    let mut issuer = Issuer::new();
    let published = issuer.public_key();
    let (state, blinded) = blind();
    let token = unblind(state, issuer.issue(blinded).unwrap(), published).unwrap();

    issuer.rotate();

    assert!(
        !issuer.verify(&token),
        "a previous-epoch token must not verify"
    );
    assert_eq!(issuer.spent_count(), 0, "rotation clears the spent set");
    assert_ne!(
        issuer.public_key(),
        published,
        "rotation republishes a new key"
    );
}
