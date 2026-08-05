//! Obfuscation demo: reshape a sample of first-hop traffic with each transport and show
//! what a censoring DPI box would see — including the entropy that flags the "looks-like-
//! nothing" transport. Run it with `cargo run -p gyre-obfs`.

use gyre_obfs::{default_transports, shannon_entropy_bits_per_byte};

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    println!("Gyre · Addition 1 — obfuscation / pluggable transports");
    println!("{}", "-".repeat(72));

    // A sample of (here, deliberately structured) first-hop bytes.
    let inner = b"GET /gyre HTTP/1.1\r\nHost: relay\r\n\r\n<inner encrypted payload>";
    let key = [0x24u8; 32];
    println!(
        "reshaping {} bytes of first-hop traffic — what a censoring DPI box sees:\n",
        inner.len()
    );
    println!("  transport     first wire bytes                          entropy (bits/byte)");
    for transport in default_transports(key) {
        let wire = transport.obfuscate(inner);
        println!(
            "  {:<11}   {:<40}   {:.2}",
            transport.name(),
            hex_prefix(&wire, 12),
            shannon_entropy_bits_per_byte(&wire)
        );
    }

    println!("{}", "-".repeat(72));
    println!("Honest ceiling: this changes APPEARANCE only — zero effect on anonymity, the");
    println!(
        "trilemma, or a global observer. 'identity' is trivially fingerprinted; 'polymorphic'"
    );
    println!(
        "looks random, but ~8 bits/byte is exactly what entropy-DPI (GFW, Wu et al. USENIX '23)"
    );
    println!(
        "now flags; 'tls-mimic' blends as TLS, but TLS-in-TLS is detectable. Agility — swapping"
    );
    println!("transports — is the real defense; no single disguise is 'unblockable'.");
}
