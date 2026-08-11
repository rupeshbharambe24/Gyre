//! **The simulation harness — the GATE, run against the real code.**
//!
//! The original GATE ([`gyre_adversary`]) is a synthetic timing *model*: it invents entry
//! times, adds sampled delays, and matches them greedily. It is fast and reproducible, but
//! it never touches the shipped implementation and its attacker is deliberately simple.
//!
//! This crate closes both gaps:
//!
//! 1. **It drives the real protocol code.** Every packet is a real Sphinx onion built by
//!    `gyre-sphinx` over the `sphinx-packet` crate, carrying a real Loopix delay
//!    schedule, peeled hop by hop with real X25519 keys. The timing an attacker sees is
//!    the timing the implementation actually produces — not a model of it.
//!
//! 2. **It uses the strongest attacker we can build.** Correlation is an assignment
//!    problem, so the attacker scores every candidate pairing by its **maximum-likelihood**
//!    cost (the Erlang density of a sum of exponential hop delays) and solves it
//!    **optimally** with the Hungarian algorithm. A greedy matcher is run on the identical
//!    cost matrix purely to quantify how much a weak attacker *understates* the risk.
//!
//! That second point matters for honesty: measuring against a weak attacker makes
//! anonymity look **better** than it is. The optimal matcher is a lower bound on what a
//! real adversary achieves, so it is the number worth reporting.
//!
//! ## What this is not
//!
//! A simulation is not a deployment. There is no real TCP, no cross-traffic, no queueing
//! contention, and no live network path — see [`sim`] for the full real-vs-modelled split.
//! For real binaries over a real network stack, the next step is the Shadow simulator,
//! which is Linux-only and documented in `docs/SIMULATION.md`.

pub mod attack;
pub mod engine;
pub mod sim;

pub use attack::{
    accuracy, assignment_cost, erlang_nll, greedy_assignment, min_cost_assignment, mle_cost_matrix,
    sequence_cost_matrix, INFEASIBLE,
};
pub use engine::Engine;
pub use sim::{repeat_outcomes, run, stats, Latency, Outcome, Scenario};
