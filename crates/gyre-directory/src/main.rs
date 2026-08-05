//! Directory / attestation demo: a t-of-n signed consensus, a single-authority forgery
//! attempt, equivocation detection, and reproducible-build attestation. Run it with
//! `cargo run -p gyre-directory`.

use gyre_directory::{
    accept_consensus, build_is_blessed, detect_equivocation, Authority, Consensus,
};

fn main() {
    println!("Gyre · Addition 4 — decentralization + attestation");
    println!("{}", "-".repeat(68));

    let authorities: Vec<Authority> = (0..5).map(|_| Authority::generate()).collect();
    let keys: Vec<_> = authorities.iter().map(Authority::public).collect();
    let threshold = 3;
    let sign = |who: &[usize], msg: &[u8]| -> Vec<_> {
        who.iter().map(|&i| (i, authorities[i].sign(msg))).collect()
    };

    println!(
        "directory consensus — {} authorities, threshold {threshold}-of-{}:",
        keys.len(),
        keys.len()
    );
    let good = Consensus::new(42, b"relay-set-v1 | mtd-params | pow=8bits".to_vec());
    let good_msg = good.signing_bytes();
    println!(
        "  signed by [0,1,2]  -> accepted: {}",
        accept_consensus(&good, &sign(&[0, 1, 2], &good_msg), &keys, threshold)
    );
    println!(
        "  signed by [0] only -> accepted: {}   (no single authority can forge)",
        accept_consensus(&good, &sign(&[0], &good_msg), &keys, threshold)
    );
    println!("{}", "-".repeat(68));

    println!("equivocation — two different bodies for the same epoch, both signed:");
    let evil = Consensus::new(42, b"relay-set-EVIL (backdoored relays)".to_vec());
    let equivocated = detect_equivocation(
        &good,
        &sign(&[0, 1, 2], &good_msg),
        &evil,
        &sign(&[2, 3, 4], &evil.signing_bytes()),
        &keys,
        threshold,
    );
    println!("  epoch 42 equivocation detected: {equivocated}   (public proof of misbehavior)");
    println!("{}", "-".repeat(68));

    println!("reproducible-build attestation — a hash is blessed only by enough rebuilders:");
    let rebuilders: Vec<Authority> = (0..4).map(|_| Authority::generate()).collect();
    let rkeys: Vec<_> = rebuilders.iter().map(Authority::public).collect();
    let blessed_hash = [0xABu8; 32];
    let bsigs: Vec<_> = [0usize, 1, 2]
        .iter()
        .map(|&i| (i, rebuilders[i].sign(&blessed_hash)))
        .collect();
    println!(
        "  build hash blessed by 3 rebuilders:              {}",
        build_is_blessed(&blessed_hash, &bsigs, &rkeys, 3)
    );
    println!(
        "  relay advertising a DIFFERENT (un-blessed) hash: {}",
        build_is_blessed(&[0xEEu8; 32], &bsigs, &rkeys, 3)
    );
    println!("{}", "-".repeat(68));
    println!("Honest ceiling (Addition 4): DETECTION, not prevention — this proves a malicious");
    println!(">=t majority cheated after the fact; it can't stop them in real time. Reproducible");
    println!(
        "builds prove binary==source, NOT that a relay actually runs that binary. Control-plane"
    );
    println!("hardening only: zero effect on the anonymity trilemma or a global observer.");
}
