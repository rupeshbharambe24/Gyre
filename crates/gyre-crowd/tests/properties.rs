//! Property-based tests for the crowd / incentive layer (P4).
//!
//! The governor's job is to never *over-promise*: its decision must be monotone in the
//! size of the concurrent crowd, and it must honour its own threshold exactly. The
//! staking model's job is to make control expensive and Sybil-splitting unprofitable.

use gyre_crowd::{reward_with_self_bond_premium, stake_to_control, Admission, Governor};
use proptest::prelude::*;

/// Order the three decisions from most to least restrictive so monotonicity is testable.
fn permissiveness(a: Admission) -> u8 {
    match a {
        Admission::Refuse => 0,
        Admission::Batch => 1,
        Admission::Admit => 2,
    }
}

proptest! {
    /// **Monotonicity.** A larger concurrent crowd is never treated more restrictively —
    /// the governor can only ever become more permissive as anonymity improves.
    #[test]
    fn admission_is_monotone_in_the_crowd(
        k in 1usize..500,
        a in 0usize..2000,
        b in 0usize..2000,
    ) {
        let governor = Governor::new(k);
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(
            permissiveness(governor.decide(lo)) <= permissiveness(governor.decide(hi)),
            "a bigger crowd must never be treated more restrictively"
        );
    }

    /// The threshold is honoured exactly: at or above `k` it always admits, and a crowd
    /// smaller than half of `k` is always refused rather than quietly served.
    #[test]
    fn the_governor_honours_its_own_threshold(k in 2usize..500, extra in 0usize..500) {
        let governor = Governor::new(k);
        prop_assert_eq!(governor.decide(k + extra), Admission::Admit);
        prop_assert_eq!(governor.decide((k - 1) / 2), Admission::Refuse);
    }

    /// A degenerate `k` never panics and always admits — `Governor::new` floors it at 1.
    #[test]
    fn a_zero_threshold_is_floored_not_fatal(set in 1usize..100) {
        prop_assert_eq!(Governor::new(0).decide(set), Admission::Admit);
    }

    /// Taking a larger share of consensus weight always costs at least as much stake, and
    /// the price is never negative.
    #[test]
    fn sybil_cost_rises_with_the_target_share(
        honest in 1.0f64..1e9,
        a in 0.0f64..0.98,
        b in 0.0f64..0.98,
    ) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(stake_to_control(lo, honest) <= stake_to_control(hi, honest));
        prop_assert!(stake_to_control(lo, honest) >= 0.0);
    }

    /// Splitting one stake across more identities always earns less than concentrating
    /// it — the self-bond premium prices Sybil-splitting out.
    #[test]
    fn splitting_stake_into_sybils_always_earns_less(
        stake in 1.0f64..1e6,
        premium in 0.0f64..2.0,
        n in 2usize..50,
    ) {
        let concentrated = reward_with_self_bond_premium(stake, 1, premium);
        let split = reward_with_self_bond_premium(stake, n, premium);
        prop_assert!(split <= concentrated, "splitting must never pay better");
        prop_assert!(split >= stake, "but an honest operator never earns less than their stake");
    }
}
