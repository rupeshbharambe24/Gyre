//! Deniability demo: hide a message in a cover object's low bits, show the carrier looks
//! unchanged, and recover it — with the honest limits printed. Run it with
//! `cargo run -p whirl-stego`.

use whirl_stego::{capacity_bytes, embed, extract};

fn main() {
    println!("Whirlpool · Addition 5 — deniability / steganography (situational)");
    println!("{}", "-".repeat(70));

    let cover: Vec<u8> = (0..1024).map(|i| (i * 7 + 13) as u8).collect();
    let secret = b"rendezvous at 0300, cookie 7f3a";

    println!(
        "cover: {} bytes  ->  capacity {} bytes (1 bit per cover byte)",
        cover.len(),
        capacity_bytes(cover.len())
    );
    let carrier = embed(&cover, secret).expect("embed");

    let changed = cover.iter().zip(&carrier).filter(|(c, s)| c != s).count();
    let high_bits_intact = cover
        .iter()
        .zip(&carrier)
        .all(|(c, s)| c & 0xFE == s & 0xFE);
    println!(
        "embedded {} bytes: {changed} cover bytes touched, high 7 bits intact: {high_bits_intact}",
        secret.len()
    );
    println!(
        "  recovered: {:?}",
        String::from_utf8_lossy(&extract(&carrier).unwrap())
    );

    println!("{}", "-".repeat(70));
    println!("Honest ceiling: LSB steganography is TRIVIALLY detectable — a warden running");
    println!("steganalysis flags the altered LSB statistics, and safe capacity collapses toward");
    println!("nothing once they do (Stegozoa). Capacity is already tiny. Add deniability ONLY if");
    println!("the adversary punishes use itself. Deniable at-rest storage (hidden volumes) is");
    println!("de-recommended entirely — prefer memory-only operation: nothing to find or compel.");
}
