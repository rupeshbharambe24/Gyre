//! Property-based tests for the inbound rotor: MTD ingress hopping, proof-of-work
//! admission, and the blind VOPRF capability token.
//!
//! The load-bearing invariants are that a client's work is *always* accepted by the
//! server (`solve` ⟹ `verify`), that the moving ingress is deterministic for a given
//! window so an authorized client and the origin never disagree, and that the token
//! issue → redeem path is single-use.

use std::time::Duration;

use gyre_shield::token::{blind, unblind, Issuer};
use gyre_shield::{difficulty_for_load, leading_zero_bits, IngressSchedule, Puzzle, ADDR_LEN};
use proptest::prelude::*;

/// Load values to test admission against. `proptest`'s `f64::ANY` only draws `NaN` about
/// 3% of the time, which is too flaky for a security invariant, so the pathological
/// values a real ratio-based estimator can produce are generated explicitly.
fn any_load() -> impl Strategy<Value = f64> {
    prop_oneof![
        Just(f64::NAN),
        Just(f64::INFINITY),
        Just(f64::NEG_INFINITY),
        -1e9f64..1e9f64,
        proptest::num::f64::ANY,
    ]
}

proptest! {
    // PoW solving and ristretto scalar mults dominate; a smaller case count keeps the
    // suite fast while still covering hundreds of challenges.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// **The admission contract.** Whatever nonce `solve` finds, `verify` accepts — the
    /// client's paid work is always valid proof to the server.
    #[test]
    fn a_solved_puzzle_always_verifies(
        challenge in prop::array::uniform32(any::<u8>()),
        bits in 0u32..=10,
    ) {
        let puzzle = Puzzle::new(challenge, bits);
        let solution = puzzle.solve();
        prop_assert!(puzzle.verify(solution.nonce), "solve must produce a verifiable nonce");
        prop_assert!(solution.attempts >= 1);
    }

    /// Difficulty rises monotonically with observed load and stays inside the designed
    /// band, so a flood always costs more than an idle-network request.
    #[test]
    fn difficulty_is_monotone_and_bounded(a in 0.0f64..=1.0, b in 0.0f64..=1.0) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(difficulty_for_load(lo) <= difficulty_for_load(hi));
        prop_assert!((8..=20).contains(&difficulty_for_load(hi)));
    }

    /// **Admission must never fail open.** For *every* `f64` — including infinities and
    /// `NaN`, which a ratio-based load estimator can genuinely produce (`0.0 / 0.0` from a
    /// reset counter) — the difficulty stays within the designed band and never drops
    /// below the base cost. A regression here would silently mean "no proof-of-work
    /// required" exactly when the load estimator is broken.
    #[test]
    fn difficulty_never_falls_below_the_base_cost_for_any_load(load in any_load()) {
        prop_assert!(
            (8..=20).contains(&difficulty_for_load(load)),
            "load {load} produced an out-of-band difficulty {}",
            difficulty_for_load(load)
        );
    }

    /// The difficulty metric can never exceed the bit length of what it measures.
    #[test]
    fn leading_zero_bits_is_bounded_by_the_input(
        bytes in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        prop_assert!(leading_zero_bits(&bytes) as usize <= bytes.len() * 8);
    }

    /// MTD: the ingress for a window is deterministic and always one of the published
    /// candidates — an authorized client and the origin must never disagree on where to
    /// meet, however the key or candidate set is shaped.
    #[test]
    fn the_moving_ingress_is_deterministic_and_always_a_real_candidate(
        key in prop::collection::vec(any::<u8>(), 1..40),
        n in 1usize..12,
        counter in any::<u64>(),
    ) {
        let candidates: Vec<[u8; ADDR_LEN]> = (0..n).map(|i| [i as u8; ADDR_LEN]).collect();
        let schedule = IngressSchedule::new(&key, Duration::from_secs(30), candidates.clone());

        let ingress = schedule.ingress_at(counter);
        prop_assert_eq!(ingress, schedule.ingress_at(counter), "must be deterministic");
        prop_assert!(candidates.contains(&ingress), "must be a published candidate");
    }

    /// The window counter advances with time and is stable inside a window — the property
    /// that lets a client track the moving target without coordination.
    #[test]
    fn the_window_counter_is_stable_within_a_window(secs in 0u64..100_000) {
        let candidates = vec![[1u8; ADDR_LEN], [2u8; ADDR_LEN]];
        let window = Duration::from_secs(60);
        let schedule = IngressSchedule::new(b"k", window, candidates);

        let base = Duration::from_secs(secs * 60);
        prop_assert_eq!(
            schedule.window_counter(base),
            schedule.window_counter(base + Duration::from_secs(59)),
        );
        prop_assert_eq!(
            schedule.window_counter(base) + 1,
            schedule.window_counter(base + window),
        );
    }

    /// An honestly issued capability token always verifies, redeems exactly once, and is
    /// rejected on any replay — the single-use guarantee the fast path depends on.
    #[test]
    fn an_issued_token_verifies_and_redeems_exactly_once(replays in 1usize..5) {
        let mut issuer = Issuer::new();
        let published = issuer.public_key();
        let (state, blinded) = blind();
        let issued = issuer.issue(blinded).expect("a fresh blinded point is valid");
        let token = unblind(state, issued, published).expect("an honest proof must verify");

        prop_assert!(issuer.verify(&token));
        prop_assert!(issuer.redeem(&token), "first redemption succeeds");
        // The generated value is actually used: *no* number of replays may ever succeed.
        for attempt in 0..replays {
            prop_assert!(!issuer.redeem(&token), "replay {attempt} must be rejected");
        }
        prop_assert_eq!(issuer.spent_count(), 1, "a replay must not grow the spent set");
    }

    /// Robustness: the issuer decompresses a client-supplied point, so arbitrary 32 bytes
    /// must be rejected cleanly rather than panicking.
    #[test]
    fn issuing_arbitrary_bytes_never_panics(blinded in prop::array::uniform32(any::<u8>())) {
        let issuer = Issuer::new();
        // Beyond not panicking: whatever comes back must be well-formed. A success on
        // random bytes would mean the point decoding accepted something it should not.
        if let Ok(issued) = issuer.issue(blinded) {
            prop_assert_eq!(issued.evaluated.len(), 32);
            prop_assert_eq!(issued.proof.len(), 64);
        }
    }
}
