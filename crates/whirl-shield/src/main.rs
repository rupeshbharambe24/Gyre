//! Inbound-shield demo: watch the ingress hop (authorized client + origin agree, a
//! scanner does not), and watch PoW admission cost rise with load while verification
//! stays a single hash. Run it with `cargo run -p whirl-shield`.

use std::time::Duration;

use whirl_shield::{difficulty_for_load, IngressSchedule, Puzzle};

fn main() {
    println!("Whirlpool · Inbound Shield — MTD ingress hopping + PoW admission");
    println!("{}", "-".repeat(70));

    // ---- Moving-target-defense ingress hopping ----
    let candidates: Vec<[u8; 32]> = (1..=8).map(|i| [i; 32]).collect();
    let window = Duration::from_secs(30);
    let key = b"origin<->client shared key";
    let origin = IngressSchedule::new(key, window, candidates.clone());
    let client = IngressSchedule::new(key, window, candidates.clone());
    let scanner = IngressSchedule::new(b"scanner's wrong guess", window, candidates);

    println!("MTD ingress hopping — origin & authorized client agree; a scanner cannot:");
    println!("  window   ingress (origin=client)   scanner target   result");
    let mut scanner_hits = 0;
    for counter in 0..6u64 {
        let real = origin.ingress_at(counter)[0];
        let client_view = client.ingress_at(counter)[0];
        let scan = scanner.ingress_at(counter)[0];
        let hit = scan == real;
        scanner_hits += u32::from(hit);
        println!(
            "   {counter:>4}           #{real:<2} (client #{client_view:<2})          #{scan:<2}           {}",
            if hit { "HIT" } else { "miss" }
        );
    }
    println!("  scanner located the ingress in {scanner_hits}/6 windows (blind chance ~1/8)");
    println!("{}", "-".repeat(70));

    // ---- Proof-of-work admission ----
    println!("PoW admission — difficulty scales with load; the server verifies in 1 hash:");
    for (label, load) in [("idle ", 0.0f64), ("busy ", 0.5), ("flood", 1.0)] {
        let bits = difficulty_for_load(load);
        let solution = Puzzle::new([0x42; 32], bits).solve();
        println!(
            "  load={label} ({load:.1})  ->  difficulty {bits:>2} bits  ->  client solved in {:>8} hashes",
            solution.attempts
        );
    }
    println!("{}", "-".repeat(70));
    println!("Honest ceiling (D22): MTD serves an authorized/closed client set, not the open web;");
    println!(
        "PoW re-prices asymmetry but a botnet outcomputes mobile clients, and it does nothing"
    );
    println!("for L3/L4 volumetric floods. A trust-topology win for tunnels, not raw capacity.");
}
