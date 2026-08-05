//! PIR demo: a client privately fetches one rendezvous descriptor from a directory
//! replicated on two servers, without either server learning which one. Run it with
//! `cargo run -p gyre-pir`.

use gyre_pir::{build_queries, recover, Directory};

fn mask_summary(mask: &[bool]) -> String {
    mask.iter().map(|&b| if b { '1' } else { '0' }).collect()
}

fn main() {
    println!("Gyre · Addition 6 — private directory retrieval (2-server PIR)");
    println!("{}", "-".repeat(70));

    let directory = Directory::new(
        (0u8..8)
            .map(|i| format!("rendezvous-descriptor-#{i}").into_bytes())
            .map(|mut record| {
                record.resize(32, 0);
                record
            })
            .collect(),
    );
    let target = 5;

    println!(
        "directory: {} records, replicated on server A and server B",
        directory.len()
    );
    println!("client privately fetches record #{target} (its target must stay secret):\n");

    let (query_a, query_b) = build_queries(directory.len(), target);
    println!(
        "  server A sees mask  {}   (random -> learns nothing)",
        mask_summary(&query_a)
    );
    println!(
        "  server B sees mask  {}   (random -> learns nothing)",
        mask_summary(&query_b)
    );

    let recovered = recover(&directory.answer(&query_a), &directory.answer(&query_b));
    let text = String::from_utf8_lossy(&recovered);
    let text = text.trim_end_matches('\0');
    println!("\n  client XORs the two answers -> {text:?}");

    println!("{}", "-".repeat(70));
    println!("Default is PIR OFF: everyone downloads the full signed consensus (nothing to");
    println!("correlate, no non-collusion assumption). Reserve PIR for the rendezvous lookup.");
    println!("Honest ceiling: information-theoretic ONLY IF the servers don't collude — and Sybil");
    println!(
        "infra is in our threat model. If they collude they XOR the masks and learn the target."
    );
}
