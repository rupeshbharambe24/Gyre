//! Endpoint-hardening demo: a forward-secret ratchet, compartmentalized personas, and a
//! uniform client fingerprint. Run it with `cargo run -p gyre-endpoint`.

use gyre_endpoint::{naive_fingerprint, uniform_fingerprint, Identity, Ratchet};

fn hex8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn main() {
    println!("Gyre · Addition 2 — endpoint hardening + data minimization");
    println!("{}", "-".repeat(68));

    println!("Forward-secret ratchet (each step a fresh key; earlier keys unrecoverable):");
    let mut ratchet = Ratchet::new([1u8; 32]);
    for i in 0..4 {
        println!(
            "  message {i}:  key {}...",
            hex8(&ratchet.next_message_key())
        );
    }
    println!("{}", "-".repeat(68));

    println!("Compartmentalized personas (cryptographically unlinkable across contexts):");
    let identity = Identity::new([9u8; 32]);
    for context in ["email", "leaks", "shopping"] {
        println!(
            "  persona {context:<9}  key {}...",
            hex8(&identity.persona(context).key())
        );
    }
    println!("{}", "-".repeat(68));

    println!("Client fingerprint (uniformity feeds the crowd):");
    println!(
        "  uniform (every client): {:?}",
        String::from_utf8_lossy(uniform_fingerprint())
    );
    println!(
        "  naive   (per user):     ...ends in the user id ({} bytes)  <- DO NOT use",
        naive_fingerprint(1).len()
    );
    println!("{}", "-".repeat(68));
    println!(
        "Honest ceiling: isolation CONTAINS a compromise, it cannot make an untrusted endpoint"
    );
    println!(
        "trusted (a live keylogger reads plaintext regardless). Forward secrecy protects PAST"
    );
    println!(
        "sessions, not an actively-compromised one; uniformity only helps with a large crowd."
    );
}
