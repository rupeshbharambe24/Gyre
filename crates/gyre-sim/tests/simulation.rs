//! End-to-end validation of the simulation harness.
//!
//! These check that the simulator behaves the way the mechanism it models must behave: no
//! mixing is perfectly correlatable, heavy mixing is not, mixing costs latency, and a
//! partial observer's reach falls off quadratically. If any of these inverts, the harness
//! is measuring something other than what it claims to.
//!
//! Sizes are deliberately small: these run in a debug build, where the real Sphinx crypto
//! is far slower than the release build the report uses.

use std::time::Duration;

use gyre_sim::sim::{run, Scenario};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A small but realistic scenario: full observation, so accuracy is purely the attacker's
/// ability to link rather than a question of coverage.
fn small(mix_ms: u64) -> Scenario {
    Scenario {
        n_flows: 24,
        packets_per_flow: 3,
        packet_interval: ms(40),
        n_relays: 8,
        hops: 3,
        mix_mean: ms(mix_ms),
        window: ms(500),
        link_latency: ms(20),
        link_jitter: ms(10),
        observed_relay_fraction: 1.0,
        cover_per_flow: 0,
        seed: 7,
    }
}

#[test]
fn every_flow_reaches_its_destination() {
    let out = run(&small(50));
    assert_eq!(out.n_flows, 24);
    assert!(
        out.latency.mean_ms > 0.0,
        "flows must actually be delivered, got {:?}",
        out.latency
    );
    // Three hops of ~20ms links is the floor; nothing can arrive faster.
    assert!(
        out.latency.p50_ms >= 60.0,
        "p50 {} ms is below the physical link floor",
        out.latency.p50_ms
    );
}

/// Without mixing, a stream's timing pattern passes through untouched and an optimal
/// attacker links essentially everything. This is the baseline the FAST lane accepts.
#[test]
fn without_mixing_streams_are_almost_perfectly_correlated() {
    let out = run(&small(0));
    assert!(
        out.accuracy_optimal > 0.85,
        "no mixing should be near-perfectly correlatable, got {}",
        out.accuracy_optimal
    );
}

/// Heavy mixing is the actual correlation-resistance lever, and it must measurably work.
#[test]
fn heavy_mixing_collapses_correlation() {
    let plain = run(&small(0)).accuracy_optimal;
    let mixed = run(&small(400)).accuracy_optimal;
    assert!(
        mixed < plain * 0.5,
        "heavy mixing should at least halve correlation: {plain} -> {mixed}"
    );
}

/// The honest cost of that resistance: mixing buys anonymity with latency, and the
/// harness must show the price rather than hide it.
#[test]
fn mixing_is_paid_for_in_latency() {
    let fast = run(&small(0)).latency.p50_ms;
    let mixed = run(&small(200)).latency.p50_ms;
    assert!(
        mixed > fast,
        "mixing must cost latency: fast p50 {fast} ms vs mixed p50 {mixed} ms"
    );
}

/// A partial observer needs BOTH ends, so coverage falls off far faster than its share of
/// relays — the quadratic that makes a large, diverse relay set matter.
///
/// Averaged over several seeds and using a reasonably sized relay pool: with only a
/// handful of relays the *realised* observed fraction swings wildly around its nominal
/// value (8 relays at p=0.5 lands on 6 often enough), which would make this flaky without
/// telling us anything about the model.
#[test]
fn partial_observation_falls_off_faster_than_linearly() {
    let full = run(&Scenario {
        observed_relay_fraction: 1.0,
        ..small(50)
    });
    assert_eq!(
        full.coverage, 1.0,
        "watching every relay must cover everything"
    );

    let seeds = 4;
    let mean_half: f64 = (0..seeds)
        .map(|s| {
            run(&Scenario {
                observed_relay_fraction: 0.5,
                n_flows: 60,
                n_relays: 40,
                seed: 100 + s,
                ..small(50)
            })
            .coverage
        })
        .sum::<f64>()
        / seeds as f64;

    // Expected ~0.25 (the square of the watched share); 0.40 leaves generous headroom
    // while still being far below the 0.5 a linear falloff would give.
    assert!(
        mean_half < 0.40,
        "half the relays should cover ~a quarter of flows, got {mean_half}"
    );
}

/// The end-to-end number is coverage x accuracy, and it can never exceed either.
#[test]
fn the_deanon_rate_is_bounded_by_coverage_and_accuracy() {
    for frac in [0.3, 0.6, 1.0] {
        let out = run(&Scenario {
            observed_relay_fraction: frac,
            ..small(50)
        });
        assert!(out.deanon_rate <= out.coverage + 1e-9);
        assert!(out.deanon_rate <= out.accuracy_optimal.max(1e-9) + 1e-9);
        assert!((0.0..=1.0).contains(&out.deanon_rate));
    }
}

/// Cover traffic costs bandwidth. It must show up in the overhead figure — and must NOT
/// be allowed to flatter the anonymity figure (anti-overclaim rule 3).
#[test]
fn cover_traffic_costs_bandwidth_and_is_excluded_from_anonymity() {
    let bare = run(&small(50));
    let covered = run(&Scenario {
        cover_per_flow: 2,
        ..small(50)
    });
    assert!(
        covered.overhead_ratio > bare.overhead_ratio,
        "cover traffic must cost overhead: {} -> {}",
        bare.overhead_ratio,
        covered.overhead_ratio
    );
    // Only real flows are ever counted as the crowd.
    assert_eq!(covered.n_flows, bare.n_flows);
}

/// Sphinx pads every packet to a fixed size, so the wire cost of a small payload is large
/// and constant. Reporting it honestly is the point of the overhead axis.
#[test]
fn the_fixed_packet_size_shows_up_as_real_overhead() {
    let out = run(&small(50));
    assert!(
        out.overhead_ratio > 1.0,
        "fixed-size padding must cost something, got {}",
        out.overhead_ratio
    );
}
