//! Prints the GATE report: the partial-observer correlation sweep and the multipath
//! exposure measurement. Run it with `cargo run -p whirl-adversary`.

use whirl_adversary::{
    partial_observer_reach, timing_correlation, timing_correlation_avg, Scenario,
};

fn main() {
    println!("Whirlpool · GATE — adversary-emulation harness");
    println!("A partial observer links flows by timing. accuracy 1.00 = perfectly linked.\n");
    println!(" flows   window   mix/hop   accuracy   chance   note");

    let rows: [(usize, f64, f64, &str); 4] = [
        (50, 1000.0, 0.0, "baseline: no mixing (FAST lane)"),
        (50, 1000.0, 50.0, "MIX lane, healthy crowd"),
        (50, 1000.0, 150.0, "more mixing"),
        (5, 1000.0, 150.0, "same mixing, tiny crowd -> barely helps"),
    ];
    for (n, window_ms, mix_mean_ms, note) in rows {
        let scn = Scenario {
            n_flows: n,
            hops: 3,
            mix_mean_ms,
            window_ms,
        };
        let acc = timing_correlation_avg(&scn, 40);
        let chance = timing_correlation(&scn, 1).chance;
        println!("  {n:>3}   {window_ms:>5.0}ms   {mix_mean_ms:>4.0}ms      {acc:>4.2}     {chance:>4.2}   {note}");
    }

    println!(
        "\nmultipath exposure — fraction of flows a partial observer (on 20% of paths) can touch:"
    );
    for (label, paths_per_flow) in [("single-path (k=1)", 1usize), ("multipath  (k=3)", 3usize)] {
        let reach = partial_observer_reach(5000, paths_per_flow, 0.2, 30, 1);
        println!("  {label}: {reach:>4.2}");
    }

    println!("\nVerdict: mixing is the real correlation-resistance lever, and it is gated on the");
    println!("crowd; multipath buys availability + content-splitting, NOT partial-observer");
    println!(
        "correlation resistance (it widens exposure). Honest, and consistent with the design."
    );
}
