//! A discrete-event simulation of the Gyre fabric that drives the **real protocol code**.
//!
//! What is real here, and what is modelled, stated plainly:
//!
//! | Real (the actual shipped code) | Modelled (simulated) |
//! |---|---|
//! | Sphinx onion construction and per-hop processing (`gyre-sphinx`, on the audited `sphinx-packet` crate) | Link latency and jitter |
//! | The per-hop Poisson delay schedule, sampled by the real Loopix sampler and sealed inside each onion | Relay selection, flow start times, packet pacing (seeded) |
//! | Real X25519 relay keys; each hop peels exactly one real layer | No queueing, bandwidth limits, or loss |
//! | Real packet sizes on the wire | Observer placement |
//!
//! The delay a relay applies is **extracted from the packet it just decrypted**, not
//! invented by the harness — so the timing being attacked is the timing the real
//! implementation produces.
//!
//! **Flows are streams, not single messages.** Each flow sends `packets_per_flow` packets
//! over one circuit, each with its own independent mixing delay. This matters enormously
//! for honesty: a single packet carries almost no timing signal, so modelling one packet
//! per flow would make correlation look far harder than it is. Real attacks correlate a
//! circuit's whole packet stream, and so does this one.
//!
//! **Honest scope.** A simulation is not a deployment: no real TCP, no cross-traffic, no
//! queueing contention. It measures the mechanism end to end against a named adversary; it
//! does not prove behaviour on the open internet.

use std::collections::HashMap;
use std::time::Duration;

use gyre_adversary::Rng;
use gyre_sphinx::{
    exponential_delays, null_surb, packet_to_bytes, wrap_with_delays, Node, Relay, SphinxPacket,
    Unwrapped, ADDRESS_LEN, DEST_ADDRESS_LEN,
};

use crate::attack::{
    accuracy, assignment_cost, greedy_assignment, min_cost_assignment, sequence_cost_matrix,
};
use crate::engine::Engine;

/// One simulation scenario.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    /// Concurrent real flows — the crowd. This is the number everything depends on.
    pub n_flows: usize,
    /// Packets each flow sends over its circuit. `1` is the pure single-message mixnet
    /// case; a realistic stream is several.
    pub packets_per_flow: usize,
    /// Mean gap between a flow's successive packets.
    pub packet_interval: Duration,
    /// Relays in the pool to choose routes from.
    pub n_relays: usize,
    /// Onion hops per route (Gyre caps this at 3 — decision **D5**).
    pub hops: usize,
    /// Mean per-hop Poisson mixing delay. `ZERO` is the FAST lane.
    pub mix_mean: Duration,
    /// Flows start uniformly at random across this window.
    pub window: Duration,
    /// Mean one-way link latency between adjacent nodes.
    pub link_latency: Duration,
    /// Uniform jitter added to each link latency, in `[0, link_jitter)`.
    pub link_jitter: Duration,
    /// Fraction of relays the observer watches. A flow is only attackable when **both**
    /// its guard and its exit are observed.
    pub observed_relay_fraction: f64,
    /// Loopix cover loops per real flow. Counted for *overhead* only — never folded into
    /// the anonymity number (standing anti-overclaim rule 3).
    pub cover_per_flow: usize,
    /// Seed for relay selection, start times, pacing, and observer placement.
    pub seed: u64,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            n_flows: 200,
            packets_per_flow: 8,
            packet_interval: Duration::from_millis(50),
            n_relays: 30,
            hops: 3,
            mix_mean: Duration::from_millis(50),
            window: Duration::from_millis(1000),
            link_latency: Duration::from_millis(20),
            link_jitter: Duration::from_millis(10),
            observed_relay_fraction: 0.2,
            cover_per_flow: 0,
            seed: 1,
        }
    }
}

/// End-to-end latency summary, in milliseconds.
#[derive(Clone, Copy, Debug, Default)]
pub struct Latency {
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
}

impl Latency {
    fn from_samples(mut samples: Vec<f64>) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        samples.sort_by(f64::total_cmp);
        let pick = |q: f64| samples[(((samples.len() - 1) as f64) * q).round() as usize];
        Self {
            mean_ms: samples.iter().sum::<f64>() / samples.len() as f64,
            p50_ms: pick(0.50),
            p90_ms: pick(0.90),
            p99_ms: pick(0.99),
        }
    }
}

/// What one simulation run measured.
#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    /// Real flows simulated.
    pub n_flows: usize,
    /// Flows the observer saw *both* ends of — the only ones it can even try to link.
    pub correlatable: usize,
    /// `correlatable / n_flows`.
    pub coverage: f64,
    /// Accuracy of the **optimal** (Hungarian, maximum-likelihood) attacker, among
    /// correlatable flows.
    pub accuracy_optimal: f64,
    /// Accuracy of a **greedy** attacker on identical information — the weaker baseline
    /// the original GATE used, kept to quantify how much it understates a real adversary.
    pub accuracy_greedy: f64,
    /// What blind guessing scores among the correlatable flows.
    pub chance: f64,
    /// **The end-to-end number:** fraction of *all* flows the optimal attacker correctly
    /// deanonymises, `coverage × accuracy_optimal`.
    pub deanon_rate: f64,
    /// End-to-end latency across all delivered packets.
    pub latency: Latency,
    /// Wire bytes sent per payload byte, including cover traffic — the trilemma's
    /// overhead axis.
    pub overhead_ratio: f64,
}

/// A packet in flight toward a relay.
enum Event {
    AtRelay {
        relay: usize,
        packet: SphinxPacket,
        flow: usize,
        hop: usize,
        sent_ns: u64,
        is_cover: bool,
    },
}

const PAYLOAD: &[u8] = b"gyre simulation payload";

fn ns(d: Duration) -> u64 {
    d.as_nanos() as u64
}

fn ms_of(t: u64) -> f64 {
    t as f64 / 1e6
}

/// Run one scenario end to end and measure it.
pub fn run(scn: &Scenario) -> Outcome {
    let n_relays = scn.n_relays.max(scn.hops).max(1);
    let hops = scn.hops.clamp(1, n_relays);
    let n_flows = scn.n_flows.max(1);
    let per_flow = scn.packets_per_flow.max(1);
    let mut rng = Rng::new(scn.seed);

    // --- Relay pool with real X25519 keys -------------------------------------------
    let relays: Vec<Relay> = (0..n_relays)
        .map(|i| {
            let mut addr = [0u8; ADDRESS_LEN];
            addr[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Relay::new(addr)
        })
        .collect();
    let by_address: HashMap<[u8; ADDRESS_LEN], usize> = relays
        .iter()
        .enumerate()
        .map(|(i, r)| (r.address(), i))
        .collect();
    let observed: Vec<bool> = (0..n_relays)
        .map(|_| rng.uniform() < scn.observed_relay_fraction)
        .collect();

    let link_delay = |rng: &mut Rng| -> u64 {
        ns(scn.link_latency) + (rng.uniform() * ns(scn.link_jitter) as f64) as u64
    };
    let pick_route = |rng: &mut Rng| -> Vec<usize> {
        let mut route = Vec::with_capacity(hops);
        while route.len() < hops {
            let c = (rng.uniform() * n_relays as f64) as usize % n_relays;
            if !route.contains(&c) {
                route.push(c);
            }
        }
        route
    };

    let mut engine: Engine<Event> = Engine::new();
    let mut entry_seen: Vec<Vec<f64>> = vec![Vec::new(); n_flows];
    let mut exit_seen: Vec<Vec<f64>> = vec![Vec::new(); n_flows];
    let mut guard_observed = vec![false; n_flows];
    let mut exit_observed = vec![false; n_flows];
    let mut latencies: Vec<f64> = Vec::with_capacity(n_flows * per_flow);
    let mut wire_bytes = 0usize;

    // --- Create the flows: one circuit each, several packets over it -----------------
    for flow in 0..n_flows {
        let route_idx = pick_route(&mut rng);
        let route: Vec<Node> = route_idx.iter().map(|&i| relays[i].as_node()).collect();
        guard_observed[flow] = observed[route_idx[0]];
        exit_observed[flow] = observed[route_idx[hops - 1]];

        let start = (rng.uniform() * ns(scn.window) as f64) as u64;
        for k in 0..per_flow {
            // Packets are paced with exponential gaps — a bursty, realistic stream rather
            // than a metronome an attacker could trivially fingerprint.
            let offset = (0..k)
                .map(|_| (rng.exp(ns(scn.packet_interval) as f64)) as u64)
                .sum::<u64>();
            // REAL Loopix delay schedule, sealed inside a REAL Sphinx onion.
            let delays = exponential_delays(hops, scn.mix_mean);
            let packet = wrap_with_delays(
                PAYLOAD,
                &route,
                [0xD5u8; DEST_ADDRESS_LEN],
                null_surb(),
                &delays,
            )
            .expect("onion construction");
            wire_bytes += packet_to_bytes(&packet).len();

            let sent = start + offset;
            engine.schedule_at(
                sent + link_delay(&mut rng),
                Event::AtRelay {
                    relay: route_idx[0],
                    packet,
                    flow,
                    hop: 0,
                    sent_ns: sent,
                    is_cover: false,
                },
            );
        }
    }

    // Cover traffic: byte-identical loops that cost bandwidth. Overhead only.
    for _ in 0..n_flows * scn.cover_per_flow {
        let route_idx = pick_route(&mut rng);
        let route: Vec<Node> = route_idx.iter().map(|&i| relays[i].as_node()).collect();
        let delays = exponential_delays(hops, scn.mix_mean);
        let packet = wrap_with_delays(
            b"cover",
            &route,
            [0xC0u8; DEST_ADDRESS_LEN],
            null_surb(),
            &delays,
        )
        .expect("cover onion");
        wire_bytes += packet_to_bytes(&packet).len();
        let start = (rng.uniform() * ns(scn.window) as f64) as u64;
        engine.schedule_at(
            start + link_delay(&mut rng),
            Event::AtRelay {
                relay: route_idx[0],
                packet,
                flow: usize::MAX,
                hop: 0,
                sent_ns: start,
                is_cover: true,
            },
        );
    }

    // --- Event loop -----------------------------------------------------------------
    while let Some((now, event)) = engine.next_event() {
        let Event::AtRelay {
            relay,
            packet,
            flow,
            hop,
            sent_ns,
            is_cover,
        } = event;

        // An observer on the guard sees the packet arrive at the first hop.
        if !is_cover && hop == 0 && observed[relay] {
            entry_seen[flow].push(ms_of(now));
        }

        // REAL processing: peel exactly one layer with this relay's own secret key and
        // recover the mixing delay that was sealed inside for it.
        match relays[relay].process(packet) {
            Ok(Unwrapped::Forward {
                next_address,
                packet,
                delay_nanos,
            }) => {
                let Some(&next) = by_address.get(&next_address) else {
                    continue; // unroutable: drop, as a real relay would
                };
                engine.schedule(
                    delay_nanos + link_delay(&mut rng),
                    Event::AtRelay {
                        relay: next,
                        packet,
                        flow,
                        hop: hop + 1,
                        sent_ns,
                        is_cover,
                    },
                );
            }
            Ok(Unwrapped::Final { .. }) => {
                if !is_cover {
                    if observed[relay] {
                        exit_seen[flow].push(ms_of(now));
                    }
                    let done = now + link_delay(&mut rng);
                    latencies.push(ms_of(done - sent_ns));
                }
            }
            Err(_) => continue, // a relay that cannot process simply drops the packet
        }
    }

    let latency = Latency::from_samples(latencies);

    // --- The attack -----------------------------------------------------------------
    // Only flows whose guard AND exit are both observed can be linked at all.
    let linkable: Vec<usize> = (0..n_flows)
        .filter(|&f| guard_observed[f] && exit_observed[f])
        .filter(|&f| !entry_seen[f].is_empty() && !exit_seen[f].is_empty())
        .collect();
    let coverage = linkable.len() as f64 / n_flows as f64;

    let (accuracy_optimal, accuracy_greedy, chance) = if linkable.len() < 2 {
        (0.0, 0.0, 0.0)
    } else {
        let n = linkable.len();
        let mut entries: Vec<Vec<f64>> = linkable.iter().map(|&f| entry_seen[f].clone()).collect();
        let mut exits: Vec<Vec<f64>> = linkable.iter().map(|&f| exit_seen[f].clone()).collect();
        for seq in entries.iter_mut().chain(exits.iter_mut()) {
            seq.sort_by(f64::total_cmp);
        }

        // The attacker receives the exit streams as an unordered set: shuffle them so
        // their position leaks nothing, and remember where each truly belongs.
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = (rng.uniform() * (i + 1) as f64) as usize % (i + 1);
            order.swap(i, j);
        }
        let shuffled: Vec<Vec<f64>> = order.iter().map(|&r| exits[r].clone()).collect();
        let mut truth = vec![0usize; n];
        for (col, &row) in order.iter().enumerate() {
            truth[row] = col;
        }

        // Between the two observation points a packet crosses `hops - 1` links and is held
        // by `hops - 1` relays — the exit's own sealed delay is never applied.
        let delay_stages = hops.saturating_sub(1).max(1);
        let offset_ms = delay_stages as f64 * scn.link_latency.as_secs_f64() * 1000.0;
        let cost = sequence_cost_matrix(
            &entries,
            &shuffled,
            delay_stages,
            scn.mix_mean.as_secs_f64() * 1000.0,
            offset_ms,
        );

        let optimal = min_cost_assignment(&cost);
        let greedy = greedy_assignment(&cost);
        debug_assert!(
            assignment_cost(&cost, &optimal) <= assignment_cost(&cost, &greedy) + 1e-6,
            "the optimal matcher must never cost more than the greedy one"
        );
        (
            accuracy(&optimal, &truth),
            accuracy(&greedy, &truth),
            1.0 / n as f64,
        )
    };

    let payload_bytes = n_flows * per_flow * PAYLOAD.len();
    Outcome {
        n_flows,
        correlatable: linkable.len(),
        coverage,
        accuracy_optimal,
        accuracy_greedy,
        chance,
        deanon_rate: coverage * accuracy_optimal,
        latency,
        overhead_ratio: wire_bytes as f64 / payload_bytes.max(1) as f64,
    }
}

/// Run a scenario `reps` times, varying only the seed, and return every outcome.
///
/// The real Loopix delay sampler draws from the OS RNG and is not seedable, so a single
/// run is a *sample*, not a fixed answer. Collecting the runs once and deriving every
/// metric from them — rather than re-simulating per metric — is both far cheaper and the
/// only way the reported columns describe the same set of runs.
pub fn repeat_outcomes(scn: &Scenario, reps: usize) -> Vec<Outcome> {
    (0..reps.max(1))
        .map(|r| {
            let mut s = *scn;
            s.seed = scn.seed.wrapping_add(r as u64);
            run(&s)
        })
        .collect()
}

/// `(mean, standard deviation)` of one metric across a set of runs.
pub fn stats(outcomes: &[Outcome], metric: impl Fn(&Outcome) -> f64) -> (f64, f64) {
    if outcomes.is_empty() {
        return (0.0, 0.0);
    }
    let values: Vec<f64> = outcomes.iter().map(metric).collect();
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    (mean, var.sqrt())
}
