//! **The GATE — an adversary-emulation harness.**
//!
//! This is the project's go/no-go instrument. It does *not* route real packets; it is
//! a small, deterministic **timing model** of the fabric's mechanisms, so it measures
//! the *mechanism* rather than the implementation's incidental jitter. Given many
//! concurrent flows, a **partial observer** tries to link entries to exits by timing,
//! and we measure how well it does under different mixing and multipath settings.
//!
//! Two experiments, and both are reported honestly — including where the design does
//! *not* help:
//!
//! 1. **Mixing vs timing correlation.** With no mixing, a timing observer links flows
//!    perfectly. Per-hop Poisson delay degrades that — but only in proportion to how
//!    much delay there is *relative to how bunched the traffic is*. So the harness also
//!    shows the crowd dependence: with few concurrent flows, mixing barely helps.
//!
//! 2. **Multipath and a partial observer.** Splitting a flow across more paths lets a
//!    partial observer *touch more flows*, not fewer (design decision **D7**:
//!    multipath widens endpoint exposure; it is not partial-observer correlation
//!    resistance). This is measured and stated plainly.
//!
//! The attacker is a simple greedy timing matcher; a stronger attacker would only make
//! anonymity look *weaker*, so using it keeps us honest about what mixing buys.

/// A tiny, fast, deterministic PRNG (xorshift64*). Deterministic on purpose: the
/// harness must be reproducible so its numbers can be trusted and regression-tested.
pub struct Rng(u64);

impl Rng {
    /// Seed the generator (any value; 0 is remapped so state is never zero).
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15 | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform sample in `[0, 1)`.
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Exponential sample with the given mean (memoryless — Loopix per-hop delay).
    pub fn exp(&mut self, mean: f64) -> f64 {
        if mean <= 0.0 {
            0.0
        } else {
            -mean * (1.0 - self.uniform()).ln()
        }
    }
}

/// One timing-correlation scenario.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    /// Number of concurrent flows (this is the crowd).
    pub n_flows: usize,
    /// Onion hops that each apply a mixing delay.
    pub hops: usize,
    /// Mean per-hop Poisson mixing delay, in milliseconds (0 = FAST lane / no mixing).
    pub mix_mean_ms: f64,
    /// Flows enter uniformly at random over `[0, window_ms]`.
    pub window_ms: f64,
}

/// The result of a timing-correlation attack.
#[derive(Clone, Copy, Debug)]
pub struct Correlation {
    /// Fraction of flows the observer linked correctly (1.0 = perfect).
    pub accuracy: f64,
    /// What random guessing would score (`1 / n_flows`).
    pub chance: f64,
}

/// Run one timing-correlation experiment: simulate `n_flows` flows, then have a
/// partial observer that sees entry and exit *times* (but not the linking) greedily
/// match exits to entries. Returns the fraction it links correctly.
pub fn timing_correlation(scn: &Scenario, seed: u64) -> Correlation {
    let n = scn.n_flows.max(1);
    let mut rng = Rng::new(seed);

    // Entry times, uniform over the window.
    let entry: Vec<f64> = (0..n).map(|_| rng.uniform() * scn.window_ms).collect();

    // Exit time = entry + sum of per-hop exponential delays.
    let exit: Vec<(f64, usize)> = entry
        .iter()
        .enumerate()
        .map(|(i, &e)| {
            let mut t = e;
            for _ in 0..scn.hops {
                t += rng.exp(scn.mix_mean_ms);
            }
            (t, i)
        })
        .collect();

    // Attack: process exits in time order; for each, subtract the *expected* delay and
    // claim the nearest still-unclaimed entry.
    let expected = scn.hops as f64 * scn.mix_mean_ms;
    let mut exits = exit;
    exits.sort_by(|a, b| a.0.total_cmp(&b.0));

    let mut claimed = vec![false; n];
    let mut correct = 0usize;
    for &(xt, true_id) in &exits {
        let target = xt - expected;
        let mut best = 0usize;
        let mut best_dist = f64::INFINITY;
        for (i, &et) in entry.iter().enumerate() {
            if !claimed[i] {
                let d = (et - target).abs();
                if d < best_dist {
                    best_dist = d;
                    best = i;
                }
            }
        }
        claimed[best] = true;
        if best == true_id {
            correct += 1;
        }
    }

    Correlation {
        accuracy: correct as f64 / n as f64,
        chance: 1.0 / n as f64,
    }
}

/// Average correlation accuracy over `runs` independent seeds (for a stable number).
pub fn timing_correlation_avg(scn: &Scenario, runs: usize) -> f64 {
    let runs = runs.max(1);
    let total: f64 = (0..runs)
        .map(|s| timing_correlation(scn, s as u64 + 1).accuracy)
        .sum();
    total / runs as f64
}

/// Measure how many flows a partial observer — placed on `observed_fraction` of all
/// paths — can *touch* (see at least one fragment of) when each flow is split across
/// `paths_per_flow` disjoint paths.
///
/// This quantifies design decision **D7**'s honest downside: more paths per flow means
/// the observer touches *more* flows, not fewer.
pub fn partial_observer_reach(
    n_flows: usize,
    paths_per_flow: usize,
    observed_fraction: f64,
    total_paths: usize,
    seed: u64,
) -> f64 {
    let total_paths = total_paths.max(1);
    let per_flow = paths_per_flow.clamp(1, total_paths);
    let mut rng = Rng::new(seed);

    let observed: Vec<bool> = (0..total_paths)
        .map(|_| rng.uniform() < observed_fraction)
        .collect();

    let mut touched = 0usize;
    for _ in 0..n_flows.max(1) {
        let mut chosen: Vec<usize> = Vec::with_capacity(per_flow);
        while chosen.len() < per_flow {
            let p = (rng.next_u64() as usize) % total_paths;
            if !chosen.contains(&p) {
                chosen.push(p);
            }
        }
        if chosen.iter().any(|&p| observed[p]) {
            touched += 1;
        }
    }
    touched as f64 / n_flows.max(1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline: with no mixing, a timing observer links every flow perfectly.
    #[test]
    fn no_mixing_is_perfectly_correlated() {
        let scn = Scenario {
            n_flows: 50,
            hops: 3,
            mix_mean_ms: 0.0,
            window_ms: 1000.0,
        };
        assert_eq!(timing_correlation_avg(&scn, 10), 1.0);
    }

    /// The go/no-go: with a real crowd and MIX-lane delay, mixing measurably cuts the
    /// observer's accuracy well below the perfect baseline.
    #[test]
    fn mixing_with_a_crowd_beats_the_baseline() {
        let mixed = Scenario {
            n_flows: 50,
            hops: 3,
            mix_mean_ms: 100.0,
            window_ms: 1000.0,
        };
        let acc = timing_correlation_avg(&mixed, 20);
        assert!(
            acc < 0.6,
            "mixing should drop correlation well below 1.0, got {acc}"
        );
    }

    /// The honest limit: with only a handful of concurrent flows, the *same* mixing is
    /// far less effective — anonymity is gated on the crowd, not on cleverness.
    #[test]
    fn mixing_effectiveness_is_gated_on_the_crowd() {
        let scenario = |n| Scenario {
            n_flows: n,
            hops: 3,
            mix_mean_ms: 100.0,
            window_ms: 1000.0,
        };
        let crowd_acc = timing_correlation_avg(&scenario(50), 20);
        let sparse_acc = timing_correlation_avg(&scenario(4), 40);
        assert!(
            sparse_acc > 2.0 * crowd_acc,
            "same mixing helps far less without a crowd: sparse={sparse_acc}, crowd={crowd_acc}"
        );
    }

    /// D7 downside, measured: splitting a flow across more paths lets a partial
    /// observer touch *more* flows.
    #[test]
    fn multipath_widens_partial_observer_reach() {
        let single = partial_observer_reach(2000, 1, 0.2, 30, 1);
        let multi = partial_observer_reach(2000, 3, 0.2, 30, 1);
        assert!(
            multi > single,
            "multipath should widen exposure: single={single}, multi={multi}"
        );
    }
}
