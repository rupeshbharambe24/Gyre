//! Flow-correlation attacks.
//!
//! An observer that watches a flow's **entry** link and its **exit** link sees two sets of
//! timestamps and must decide which exit belongs to which entry. That is an *assignment
//! problem*, and how well it is solved is the difference between an attacker we flatter
//! ourselves against and one that tells us the truth.
//!
//! This module provides both, over an identical cost matrix so the comparison is
//! controlled:
//!
//! - [`greedy_assignment`] — each entry grabs its own cheapest unclaimed exit. Cheap,
//!   myopic, and **weaker than a real adversary**.
//! - [`min_cost_assignment`] — the Hungarian (Kuhn–Munkres) algorithm, which finds the
//!   globally minimum-cost perfect matching in `O(n³)`. No attacker using this cost
//!   function can do better, so it is the honest thing to measure against.
//!
//! The cost itself is a **maximum-likelihood** score ([`erlang_nll`]): the sum of `k`
//! independent exponential per-hop delays is Erlang-distributed, so the negative
//! log-likelihood of an observed entry→exit gap is the principled cost of pairing them.
//! Ordering an exit *before* its candidate entry is impossible, and priced as such.

/// Cost assigned to an impossible pairing (an exit observed before its entry). Large but
/// finite, so the assignment stays numerically well-behaved.
pub const INFEASIBLE: f64 = 1e12;

/// Negative log-likelihood of an entry→exit gap of `delta_ms`, given `hops` independent
/// exponential mixing delays of mean `mean_ms` each.
///
/// The sum of `k` i.i.d. `Exp(μ)` delays is `Erlang(k, μ)`, whose log-density is
/// `(k-1)·ln Δ − Δ/μ` up to constants that are identical for every candidate pair and so
/// cannot change which assignment wins. With no mixing (`mean_ms == 0`) the distribution
/// collapses to a point mass and the best an attacker can do is prefer the *closest*
/// preceding entry — which is what returning `delta_ms` scores.
pub fn erlang_nll(delta_ms: f64, hops: usize, mean_ms: f64) -> f64 {
    // An exit cannot precede its own entry. The `is_finite` guard is load-bearing, not
    // decoration: every comparison against NaN is false, so a bare `delta_ms <= 0.0`
    // would let a NaN gap fall through and poison the cost matrix with NaN — which would
    // silently corrupt the assignment rather than reject the pairing.
    if !delta_ms.is_finite() || delta_ms <= 0.0 {
        return INFEASIBLE;
    }
    if mean_ms <= 0.0 {
        return delta_ms; // no mixing: nearest preceding entry wins
    }
    let k = hops.max(1) as f64;
    delta_ms / mean_ms - (k - 1.0) * delta_ms.ln()
}

/// Build the `entries × exits` cost matrix an attacker would score pairings with.
///
/// `entry_ms[i]` is when flow `i` was seen entering; `exit_ms[j]` is when the `j`-th exit
/// was seen. Both must have the same length (a perfect matching is assumed — the attacker
/// knows every observed flow both entered and exited).
///
/// `delay_stages` is how many hops actually apply a mixing delay between the two
/// observation points, and `network_offset_ms` is the constant propagation time across
/// the links between them. Subtracting that offset before scoring gives the attacker the
/// *correct* likelihood model, which is the point: we measure against the strongest
/// attacker we can construct, not a convenient one.
pub fn mle_cost_matrix(
    entry_ms: &[f64],
    exit_ms: &[f64],
    delay_stages: usize,
    mean_ms: f64,
    network_offset_ms: f64,
) -> Vec<Vec<f64>> {
    entry_ms
        .iter()
        .map(|&e| {
            exit_ms
                .iter()
                .map(|&x| {
                    let gap = x - e;
                    if gap <= 0.0 {
                        return INFEASIBLE; // an exit cannot precede its own entry
                    }
                    // Jitter can push a genuine pair slightly under the nominal network
                    // time, so floor the residual instead of declaring it impossible.
                    let mixing = (gap - network_offset_ms).max(1e-6);
                    erlang_nll(mixing, delay_stages, mean_ms)
                })
                .collect()
        })
        .collect()
}

/// Cost matrix for **stream** correlation: each flow contributes a *sequence* of observed
/// packet times at entry and at exit.
///
/// This is the realistic threat. A single packet carries very little timing signal, but a
/// circuit carrying `m` packets gives the attacker `m` independent likelihood terms, and
/// the log-likelihood adds — so confidence grows with flow length. Modelling one packet
/// per flow would make correlation look far harder than it is.
///
/// Sequences are compared position-by-position after sorting (mixing can reorder packets
/// within a circuit, which shows up as noise in the score rather than as a hard failure).
pub fn sequence_cost_matrix(
    entry: &[Vec<f64>],
    exit: &[Vec<f64>],
    delay_stages: usize,
    mean_ms: f64,
    network_offset_ms: f64,
) -> Vec<Vec<f64>> {
    entry
        .iter()
        .map(|e_seq| {
            exit.iter()
                .map(|x_seq| {
                    let pairs = e_seq.len().min(x_seq.len());
                    if pairs == 0 {
                        return INFEASIBLE;
                    }
                    let total: f64 = (0..pairs)
                        .map(|k| {
                            let gap = x_seq[k] - e_seq[k];
                            if gap <= 0.0 {
                                return INFEASIBLE;
                            }
                            let mixing = (gap - network_offset_ms).max(1e-6);
                            erlang_nll(mixing, delay_stages, mean_ms)
                        })
                        .sum();
                    total / pairs as f64
                })
                .collect()
        })
        .collect()
}

/// A myopic matcher: each row, in order, claims its cheapest still-unclaimed column.
///
/// This is the shape of attacker the original GATE used. It is kept **only** as a
/// baseline, to measure how much such an attacker *understates* a real one.
pub fn greedy_assignment(cost: &[Vec<f64>]) -> Vec<usize> {
    let n = cost.len();
    let mut claimed = vec![false; n];
    let mut assign = vec![0usize; n];
    for (i, row) in cost.iter().enumerate() {
        let mut best = usize::MAX;
        let mut best_cost = f64::INFINITY;
        for (j, &c) in row.iter().enumerate() {
            if !claimed[j] && c < best_cost {
                best_cost = c;
                best = j;
            }
        }
        // Every row finds a column while the matrix is square and n columns exist.
        let best = if best == usize::MAX { i } else { best };
        claimed[best] = true;
        assign[i] = best;
    }
    assign
}

/// Minimum-cost perfect matching on a square cost matrix — the Hungarian / Kuhn–Munkres
/// algorithm with potentials, `O(n³)`.
///
/// Returns `assign` where `assign[i]` is the column matched to row `i`. The total cost of
/// this matching is provably minimal, so it bounds what *any* attacker can achieve with
/// this cost function.
pub fn min_cost_assignment(cost: &[Vec<f64>]) -> Vec<usize> {
    let n = cost.len();
    if n == 0 {
        return Vec::new();
    }
    let m = cost[0].len();
    assert_eq!(n, m, "min_cost_assignment expects a square matrix");

    // 1-indexed internally (index 0 is the sentinel the augmenting path starts from).
    let mut u = vec![0.0f64; n + 1];
    let mut v = vec![0.0f64; m + 1];
    let mut p = vec![0usize; m + 1]; // p[j] = row currently matched to column j
    let mut way = vec![0usize; m + 1];

    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0usize;
        let mut minv = vec![f64::INFINITY; m + 1];
        let mut used = vec![false; m + 1];

        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = f64::INFINITY;
            let mut j1 = 0usize;

            for j in 1..=m {
                if !used[j] {
                    let cur = cost[i0 - 1][j - 1] - u[i0] - v[j];
                    if cur < minv[j] {
                        minv[j] = cur;
                        way[j] = j0;
                    }
                    if minv[j] < delta {
                        delta = minv[j];
                        j1 = j;
                    }
                }
            }
            // `delta` is finite while any column is unused, which holds until we augment.
            for j in 0..=m {
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        // Walk the augmenting path back, flipping matches.
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }

    let mut assign = vec![0usize; n];
    for j in 1..=m {
        if p[j] != 0 {
            assign[p[j] - 1] = j - 1;
        }
    }
    assign
}

/// Total cost of an assignment — used to compare matchers on identical information.
pub fn assignment_cost(cost: &[Vec<f64>], assign: &[usize]) -> f64 {
    assign.iter().enumerate().map(|(i, &j)| cost[i][j]).sum()
}

/// Fraction of rows matched to their true column.
pub fn accuracy(assign: &[usize], truth: &[usize]) -> f64 {
    if assign.is_empty() {
        return 0.0;
    }
    let correct = assign.iter().zip(truth).filter(|(a, t)| **a == **t).count();
    correct as f64 / assign.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force minimum over all permutations, for validating the Hungarian solver.
    fn brute_force_min(cost: &[Vec<f64>]) -> f64 {
        let n = cost.len();
        let mut idx: Vec<usize> = (0..n).collect();
        let mut best = f64::INFINITY;
        permute(&mut idx, 0, &mut |perm| {
            let total: f64 = perm.iter().enumerate().map(|(i, &j)| cost[i][j]).sum();
            if total < best {
                best = total;
            }
        });
        best
    }

    fn permute(v: &mut Vec<usize>, k: usize, f: &mut impl FnMut(&[usize])) {
        if k == v.len() {
            f(v);
            return;
        }
        for i in k..v.len() {
            v.swap(k, i);
            permute(v, k + 1, f);
            v.swap(k, i);
        }
    }

    fn lcg(seed: &mut u64) -> f64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*seed >> 33) as f64) / ((1u64 << 31) as f64)
    }

    #[test]
    fn hungarian_matches_brute_force_on_random_matrices() {
        let mut seed = 42u64;
        for n in 1..=6 {
            for _ in 0..20 {
                let cost: Vec<Vec<f64>> = (0..n)
                    .map(|_| (0..n).map(|_| (lcg(&mut seed) * 100.0).round()).collect())
                    .collect();
                let assign = min_cost_assignment(&cost);

                // A valid permutation...
                let mut seen = assign.clone();
                seen.sort_unstable();
                assert_eq!(seen, (0..n).collect::<Vec<_>>(), "must be a permutation");

                // ...and optimal.
                let got = assignment_cost(&cost, &assign);
                let want = brute_force_min(&cost);
                assert!(
                    (got - want).abs() < 1e-6,
                    "n={n}: hungarian {got} != brute force {want}"
                );
            }
        }
    }

    /// The load-bearing claim: the optimal matcher is never worse than the greedy one.
    #[test]
    fn optimal_is_never_more_expensive_than_greedy() {
        let mut seed = 7u64;
        for n in 2..=8 {
            for _ in 0..40 {
                let cost: Vec<Vec<f64>> = (0..n)
                    .map(|_| (0..n).map(|_| lcg(&mut seed) * 50.0).collect())
                    .collect();
                let opt = assignment_cost(&cost, &min_cost_assignment(&cost));
                let greedy = assignment_cost(&cost, &greedy_assignment(&cost));
                assert!(
                    opt <= greedy + 1e-9,
                    "n={n}: optimal {opt} should not exceed greedy {greedy}"
                );
            }
        }
    }

    /// An identity-shaped cost matrix must recover the identity matching exactly.
    #[test]
    fn a_clear_signal_is_matched_perfectly() {
        let n = 6;
        let cost: Vec<Vec<f64>> = (0..n)
            .map(|i| (0..n).map(|j| if i == j { 0.0 } else { 10.0 }).collect())
            .collect();
        let assign = min_cost_assignment(&cost);
        assert_eq!(assign, (0..n).collect::<Vec<_>>());
        assert_eq!(accuracy(&assign, &(0..n).collect::<Vec<_>>()), 1.0);
    }

    #[test]
    fn an_exit_before_its_entry_is_priced_as_impossible() {
        assert_eq!(erlang_nll(-1.0, 3, 50.0), INFEASIBLE);
        assert_eq!(erlang_nll(0.0, 3, 50.0), INFEASIBLE);
        assert!(erlang_nll(150.0, 3, 50.0) < INFEASIBLE);
    }

    /// A non-finite gap must be rejected, not propagated. Every comparison against `NaN`
    /// is false, so a naive `delta <= 0.0` check would let one through and turn the whole
    /// cost matrix into `NaN` — silently corrupting the assignment instead of refusing the
    /// pairing.
    #[test]
    fn a_non_finite_gap_never_poisons_the_cost_matrix() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                erlang_nll(bad, 3, 50.0),
                INFEASIBLE,
                "gap {bad} must be refused"
            );
        }
        // And it stays out of a built matrix, so the solver never sees a NaN.
        let cost = mle_cost_matrix(&[0.0, f64::NAN], &[100.0, 200.0], 2, 50.0, 40.0);
        assert!(
            cost.iter().flatten().all(|c| c.is_finite()),
            "no cell may be NaN: {cost:?}"
        );
    }

    /// With no mixing the cost is monotone in the gap, so the nearest preceding entry is
    /// preferred — the strongest possible attack when there is nothing to hide behind.
    #[test]
    fn without_mixing_the_closest_entry_is_preferred() {
        assert!(erlang_nll(10.0, 3, 0.0) < erlang_nll(20.0, 3, 0.0));
    }

    /// The Erlang cost is minimised near the distribution's mode, `(k-1)·μ`.
    #[test]
    fn the_likelihood_peaks_near_the_erlang_mode() {
        let (k, mu) = (3usize, 50.0);
        let mode = (k as f64 - 1.0) * mu;
        let at_mode = erlang_nll(mode, k, mu);
        assert!(at_mode < erlang_nll(mode * 0.2, k, mu));
        assert!(at_mode < erlang_nll(mode * 5.0, k, mu));
    }

    #[test]
    fn empty_and_single_element_matrices_are_handled() {
        assert!(min_cost_assignment(&[]).is_empty());
        assert_eq!(min_cost_assignment(&[vec![3.0]]), vec![0]);
    }
}
