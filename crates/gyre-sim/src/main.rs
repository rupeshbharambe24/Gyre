//! The simulation report: runs the real fabric under a partial observer and prints what
//! it measured. Run with `cargo run --release -p gyre-sim` (release matters — the real
//! Sphinx crypto is far slower in a debug build).

use std::time::Duration;

use gyre_sim::sim::{repeat_outcomes, run, stats, Scenario, Traffic};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Independent runs per row. Each row's columns all come from this same set of runs.
const REPS: usize = 8;

fn main() {
    let base = Scenario {
        n_flows: 150,
        packets_per_flow: 8,
        packet_interval: ms(50),
        n_relays: 30,
        hops: 3,
        window: ms(1000),
        link_latency: ms(20),
        link_jitter: ms(10),
        observed_relay_fraction: 1.0,
        cover_per_flow: 0,
        traffic: Traffic::Uniform,
        seed: 1,
        mix_mean: ms(0),
    };

    println!("Gyre · simulation harness — the real fabric under a partial observer");
    println!("{}", "=".repeat(78));
    println!(
        "Real code: Sphinx onions, X25519 relay keys, the Loopix delay sampler, real\n\
         packet sizes. Modelled: link latency/jitter, relay selection, flow pacing.\n\
         {} concurrent flows x {} packets per circuit. Each figure is the mean of {} runs.",
        base.n_flows, base.packets_per_flow, REPS
    );

    // ---------------------------------------------------------------------------
    println!("\n\n1 · MIXING vs a MAXIMUM-LIKELIHOOD, OPTIMAL-ASSIGNMENT ATTACKER");
    println!("{}", "-".repeat(78));
    println!("Every relay watched, so coverage is 1.0 and the number is purely the");
    println!("attacker's ability to link streams it can see both ends of.");
    println!(
        "\n{:>9}  {:>6}  {:>18}  {:>14}  {:>8}",
        "mix/hop", "lane", "optimal acc.", "greedy acc.", "chance"
    );
    for (delay, lane) in [
        (0u64, "FAST"),
        (10, "MIX"),
        (50, "MIX"),
        (150, "MIX"),
        (500, "MIX"),
    ] {
        let outcomes = repeat_outcomes(
            &Scenario {
                mix_mean: ms(delay),
                ..base
            },
            REPS,
        );
        let (opt, sd) = stats(&outcomes, |o| o.accuracy_optimal);
        let (grd, _) = stats(&outcomes, |o| o.accuracy_greedy);
        let (chance, _) = stats(&outcomes, |o| o.chance);
        println!(
            "{:>7}ms  {:>6}  {:>11.3} ±{:.3}  {:>14.3}  {:>8.4}",
            delay, lane, opt, sd, grd, chance
        );
    }
    println!(
        "\n  The greedy column is the attacker shape the ORIGINAL GATE used. Wherever it\n\
         \x20 scores below the optimal column, that weaker attacker was understating the\n\
         \x20 risk — i.e. making our anonymity look better than it is."
    );

    // ---------------------------------------------------------------------------
    println!("\n\n2 · THE CROWD IS THE BINDING CONSTRAINT");
    println!("{}", "-".repeat(78));
    println!("Identical 150ms/hop mixing; only the number of concurrent flows changes.");
    println!(
        "\n{:>7}  {:>18}  {:>9}  {:>16}",
        "flows", "optimal acc.", "chance", "acc. vs chance"
    );
    for n in [4usize, 10, 25, 50, 100, 150] {
        let outcomes = repeat_outcomes(
            &Scenario {
                n_flows: n,
                mix_mean: ms(150),
                ..base
            },
            REPS,
        );
        let (opt, sd) = stats(&outcomes, |o| o.accuracy_optimal);
        let chance = 1.0 / n as f64;
        println!(
            "{:>7}  {:>11.3} ±{:.3}  {:>9.4}  {:>15.1}x",
            n,
            opt,
            sd,
            chance,
            opt / chance
        );
    }
    println!(
        "\n  Accuracy falls as the crowd grows — but so does chance. A small crowd stays\n\
         \x20 catastrophically above guessing however hard you mix."
    );

    // ---------------------------------------------------------------------------
    println!("\n\n3 · PARTIAL OBSERVER — THE END-TO-END DEANONYMISATION RATE");
    println!("{}", "-".repeat(78));
    println!("A flow can only be linked when the observer holds BOTH its guard and its");
    println!("exit. deanon rate = coverage x accuracy — the honest headline number.");
    println!(
        "\n{:>9}  {:>10}  {:>10}  {:>14}  {:>18}",
        "watched", "coverage", "linkable", "optimal acc.", "deanon rate"
    );
    for frac in [0.1f64, 0.2, 0.35, 0.5, 1.0] {
        let outcomes = repeat_outcomes(
            &Scenario {
                observed_relay_fraction: frac,
                mix_mean: ms(50),
                ..base
            },
            REPS,
        );
        let (cov, _) = stats(&outcomes, |o| o.coverage);
        let (linkable, _) = stats(&outcomes, |o| o.correlatable as f64);
        let (acc, _) = stats(&outcomes, |o| o.accuracy_optimal);
        let (deanon, sd) = stats(&outcomes, |o| o.deanon_rate);
        // Below two linkable flows there is nothing to match, so accuracy is undefined
        // rather than zero — printing 0.000 there would read as "perfectly anonymous".
        let acc_col = if linkable < 2.0 {
            "     n/a".to_string()
        } else {
            format!("{acc:>8.3}")
        };
        println!(
            "{:>8.0}%  {:>10.3}  {:>10.1}  {:>14}  {:>11.3} ±{:.3}",
            frac * 100.0,
            cov,
            linkable,
            acc_col,
            deanon,
            sd
        );
    }
    println!(
        "\n  Coverage tracks (watched fraction)^2 — an observer needs both ends. But note\n\
         \x20 the accuracy column: the FEW flows a small observer does see both ends of are\n\
         \x20 linked with near-certainty, because that correlatable set is itself tiny.\n\
         \x20 Low coverage is not safety for the flows inside it."
    );

    // ---------------------------------------------------------------------------
    println!("\n\n4 · THE TRILEMMA, MEASURED — anonymity vs latency vs overhead");
    println!("{}", "-".repeat(78));
    println!("The same fabric at different points on the dial. Nothing here beats physics;");
    println!("the design just makes the trade explicit and lets a flow choose.");
    println!(
        "\n{:>9}  {:>6}  {:>14}  {:>9}  {:>9}  {:>10}",
        "mix/hop", "cover", "optimal acc.", "p50 ms", "p99 ms", "overhead"
    );
    for (delay, cover) in [(0u64, 0usize), (50, 0), (150, 0), (150, 1), (150, 3)] {
        let outcomes = repeat_outcomes(
            &Scenario {
                mix_mean: ms(delay),
                cover_per_flow: cover,
                ..base
            },
            REPS,
        );
        let (acc, _) = stats(&outcomes, |o| o.accuracy_optimal);
        let (p50, _) = stats(&outcomes, |o| o.latency.p50_ms);
        let (p99, _) = stats(&outcomes, |o| o.latency.p99_ms);
        let (ovh, _) = stats(&outcomes, |o| o.overhead_ratio);
        println!(
            "{:>7}ms  {:>6}  {:>14.3}  {:>9.1}  {:>9.1}  {:>9.1}x",
            delay, cover, acc, p50, p99, ovh
        );
    }
    println!(
        "\n  Cover traffic costs bandwidth and buys nothing in the accuracy column —\n\
         \x20 deliberately. Counting decoys as if they were real senders is banned\n\
         \x20 (anti-overclaim rule 3), so anonymity is measured over REAL flows only."
    );

    // ---------------------------------------------------------------------------
    println!("\n\n5 · ONE DETAILED RUN");
    println!("{}", "-".repeat(78));
    let o = run(&Scenario {
        mix_mean: ms(50),
        observed_relay_fraction: 0.35,
        ..base
    });
    println!("  flows                     {}", o.n_flows);
    println!(
        "  correlatable              {} ({:.1}% coverage)",
        o.correlatable,
        o.coverage * 100.0
    );
    println!(
        "  optimal accuracy          {:.3}  (greedy {:.3}, chance {:.4})",
        o.accuracy_optimal, o.accuracy_greedy, o.chance
    );
    println!("  deanon rate               {:.3}", o.deanon_rate);
    println!(
        "  latency mean/p50/p90/p99  {:.1} / {:.1} / {:.1} / {:.1} ms",
        o.latency.mean_ms, o.latency.p50_ms, o.latency.p90_ms, o.latency.p99_ms
    );
    println!(
        "  wire overhead             {:.1}x payload",
        o.overhead_ratio
    );

    // ---------------------------------------------------------------------------
    println!("\n\n6 · REALISTIC, HETEROGENEOUS TRAFFIC (the synthetic crowd, for measurement)");
    println!("{}", "-".repeat(78));
    println!("A real crowd is not synchronized. Here each flow draws a profile — mostly short");
    println!("interactive/web bursts, some sparse messaging, a few long bulk transfers — so");
    println!("the modelled crowd is as diverse as a real population. Every flow is still an");
    println!("INDEPENDENT sender; this is realism for measurement, not cover posing as senders.");
    println!(
        "\n{:>9}  {:>10}  {:>18}  {:>10}",
        "mix/hop", "traffic", "optimal acc.", "chance"
    );
    for (delay, traffic) in [
        (50u64, Traffic::Uniform),
        (50, Traffic::Mixed),
        (150, Traffic::Uniform),
        (150, Traffic::Mixed),
    ] {
        let outcomes = repeat_outcomes(
            &Scenario {
                mix_mean: ms(delay),
                traffic,
                ..base
            },
            REPS,
        );
        let (opt, sd) = stats(&outcomes, |o| o.accuracy_optimal);
        let (chance, _) = stats(&outcomes, |o| o.chance);
        let label = match traffic {
            Traffic::Uniform => "uniform",
            Traffic::Mixed => "mixed",
        };
        println!(
            "{:>7}ms  {:>10}  {:>11.3} ±{:.3}  {:>8.4}",
            delay, label, opt, sd, chance
        );
    }
    println!(
        "\n  Diversity does not rescue a small crowd, and it is not a free anonymity win:\n\
         \x20 the attacker still links what it can see both ends of. It matters because the\n\
         \x20 uniform model is an ARTIFICIALLY EASY block to correlate; measuring on a\n\
         \x20 realistic mix keeps us honest about what a real population would give."
    );

    // ---------------------------------------------------------------------------
    println!("\n\n7 · SCALE — the crowd curve at real-world size (partial observer, mixed)");
    println!("{}", "-".repeat(78));
    println!("The whole point of the crowd is that it must be LARGE and REAL. Published mixnet");
    println!("studies sweep 10^2-10^5 users; this testbed now runs there. A 20%-relay observer");
    println!("watches a heterogeneous crowd; deanon rate = coverage x accuracy is the headline.");
    // Fewer reps on the heavy rows: generation is O(flows x packets) of real Sphinx onions.
    const SCALE_REPS: usize = 4;
    println!(
        "\n{:>9}  {:>10}  {:>10}  {:>14}  {:>16}",
        "flows", "coverage", "linkable", "optimal acc.", "deanon rate"
    );
    for n in [150usize, 1000, 3000, 10000] {
        let outcomes = repeat_outcomes(
            &Scenario {
                n_flows: n,
                mix_mean: ms(50),
                observed_relay_fraction: 0.2,
                traffic: Traffic::Mixed,
                ..base
            },
            SCALE_REPS,
        );
        let (cov, _) = stats(&outcomes, |o| o.coverage);
        let (linkable, _) = stats(&outcomes, |o| o.correlatable as f64);
        let (acc, _) = stats(&outcomes, |o| o.accuracy_optimal);
        let (deanon, sd) = stats(&outcomes, |o| o.deanon_rate);
        let acc_col = if linkable < 2.0 {
            "     n/a".to_string()
        } else {
            format!("{acc:>8.3}")
        };
        println!(
            "{:>9}  {:>10.3}  {:>10.1}  {:>14}  {:>11.4} ±{:.4}",
            n, cov, linkable, acc_col, deanon, sd
        );
    }
    println!(
        "\n  This is the number the crowd actually moves: as the real, independent population\n\
         \x20 grows, the end-to-end deanonymisation rate falls. No amount of synthetic cover\n\
         \x20 substitutes for it — only more real senders do (sections 2 and 4 together)."
    );

    println!("\n{}", "=".repeat(78));
    println!("HONEST READING");
    println!("{}", "=".repeat(78));
    println!(
        "· Mixing is the real correlation-resistance lever, and it works — measured here\n\
         \x20 against an OPTIMAL maximum-likelihood attacker, not a convenient one.\n\
         · Anonymity is the size of the concurrent crowd. No delay setting rescues a\n\
         \x20 small one: the accuracy-vs-chance ratio stays high however hard you mix.\n\
         · Streams are far easier to correlate than single messages. These numbers use\n\
         \x20 multi-packet circuits precisely because one packet per flow would flatter us.\n\
         · This is a SIMULATION: real protocol code, modelled network. No TCP, no\n\
         \x20 cross-traffic, no queueing. It does not prove behaviour on the open internet."
    );
}
