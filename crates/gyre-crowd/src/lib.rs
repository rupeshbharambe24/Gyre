//! **P4 — the crowd / incentive layer (the binding constraint).**
//!
//! The GATE measured it directly: anonymity equals the size of the *concurrent* crowd, and
//! no cryptographic cleverness manufactures one. P4 is the demand-side work. Two pieces are
//! code (the rest — attracting users, running a testnet, a token economy — is not):
//!
//! - A **k-anonymity admission governor** that refuses to *promise* anonymity it cannot
//!   deliver below a safe concurrent set size. It refuses to lie; it does **not** make a
//!   crowd.
//! - A **staking model** that *prices* a Sybil takeover and penalizes splitting stake into
//!   many identities (a self-bond premium). It raises the attacker's cost; it does **not**
//!   prevent a well-funded one — staking converts Sybil resistance into wealth
//!   concentration, and stake-decentralization is not user-decentralization.
//!
//! **Honest bottom line:** neither mechanism creates the crowd. That remains a demand-side
//! adoption problem, and it is the single thing every competitor comparison came down to.

/// What the governor decides for a given concurrent anonymity set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The set is large enough — route now with the promised anonymity.
    Admit,
    /// Too small to promise interactive anonymity, but close — hold in a higher-latency
    /// batch (padded with cover) until the set reaches `k`.
    Batch,
    /// Far too small — refuse rather than offer anonymity that isn't there.
    Refuse,
}

/// A k-anonymity admission governor: it will only *promise* anonymity when the concurrent
/// set is at least `k`.
pub struct Governor {
    k: usize,
}

impl Governor {
    /// A governor requiring a concurrent set of at least `k`.
    pub fn new(k: usize) -> Self {
        Self { k: k.max(1) }
    }

    /// Decide, given the current concurrent (effective) anonymity set size.
    pub fn decide(&self, effective_set: usize) -> Admission {
        if effective_set >= self.k {
            Admission::Admit
        } else if effective_set * 2 >= self.k {
            Admission::Batch
        } else {
            Admission::Refuse
        }
    }
}

/// The stake an attacker needs to control `fraction` of consensus weight, given the total
/// `honest_stake`. It prices the attack; it does not prevent it.
///
/// To reach `attacker / (attacker + honest) = f`, the attacker needs
/// `attacker = f * honest / (1 - f)`.
pub fn stake_to_control(fraction: f64, honest_stake: f64) -> f64 {
    let f = fraction.clamp(0.0, 0.999);
    f * honest_stake / (1.0 - f)
}

/// Reward for a total `stake` operated as `identities` relays under a self-bond `premium`.
///
/// The premium rewards *concentration*: a single well-bonded relay earns
/// `stake * (1 + premium)`, while the same stake split across `n` Sybil identities earns
/// only `stake * (1 + premium / n)`. So splitting into Sybils is penalized.
pub fn reward_with_self_bond_premium(stake: f64, identities: usize, premium: f64) -> f64 {
    let self_bond_fraction = 1.0 / identities.max(1) as f64;
    stake * (1.0 + premium * self_bond_fraction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_governor_refuses_to_promise_anonymity_it_cannot_deliver() {
        let g = Governor::new(100);
        assert_eq!(g.decide(500), Admission::Admit);
        assert_eq!(g.decide(100), Admission::Admit);
        assert_eq!(g.decide(60), Admission::Batch); // >= k/2, accumulate toward k
        assert_eq!(g.decide(10), Admission::Refuse); // far too small — refuse, don't lie
    }

    #[test]
    fn staking_prices_a_sybil_takeover() {
        let honest = 1_000_000.0;
        // To control half the weight you must match the honest stake.
        assert!((stake_to_control(0.5, honest) - honest).abs() < 1e-6);
        // A super-majority costs strictly more, and cost rises with the target share.
        assert!(stake_to_control(0.67, honest) > stake_to_control(0.51, honest));
        assert!(stake_to_control(0.51, honest) > stake_to_control(0.34, honest));
    }

    #[test]
    fn splitting_stake_into_sybils_is_penalized() {
        let stake = 1000.0;
        let premium = 0.5;
        let concentrated = reward_with_self_bond_premium(stake, 1, premium);
        let split = reward_with_self_bond_premium(stake, 10, premium);
        assert!(
            concentrated > split,
            "one bonded relay must out-earn the same stake split into Sybils"
        );
    }
}
