//! Inbound-admission crypto benchmarks: the blind VOPRF capability-token stages and
//! the proof-of-work puzzle (client `solve` cost vs. server `verify` cost).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use gyre_shield::pow::{PowAlgorithm, Sha256Pow};
use gyre_shield::token::{blind, unblind, Issued, Issuer};

/// Mint a token via the F14-authorized path (fetch challenge, solve it, present the solution).
/// The puzzle solve is not part of what we measure — the client pays it — so callers do it in
/// setup, not in the measured closure.
fn mint(issuer: &mut Issuer, blinded: [u8; 32]) -> Issued {
    let now = std::time::Duration::from_secs(0);
    let challenge = issuer.issuance_challenge(now);
    let solution = challenge.solve().expect("SHA-256 supported");
    issuer
        .issue(&challenge, &solution, blinded, now)
        .expect("authorized issue")
}

/// The four VOPRF stages: client `blind`, issuer `issue`, client `unblind`, issuer
/// `verify`. Each is a small number of ristretto scalar multiplications.
fn voprf(c: &mut Criterion) {
    let mut g = c.benchmark_group("voprf_token");

    g.bench_function("blind", |b| b.iter(|| black_box(blind())));

    // `issue` now redeems a solved issuance challenge (F14) before the DLEQ blind-evaluate. A
    // fresh issuer per iteration keeps the single-use spent set from growing and skewing the
    // measurement; the puzzle solve and keygen happen in setup, unmeasured.
    g.bench_function("issue", |b| {
        b.iter_batched(
            || {
                let issuer = Issuer::new();
                let now = std::time::Duration::from_secs(0);
                let challenge = issuer.issuance_challenge(now);
                let solution = challenge.solve().expect("SHA-256 supported");
                let (_state, blinded) = blind();
                (issuer, challenge, solution, blinded, now)
            },
            |(mut issuer, challenge, solution, blinded, now)| {
                black_box(issuer.issue(&challenge, &solution, blinded, now).unwrap())
            },
            BatchSize::SmallInput,
        )
    });

    g.bench_function("unblind", |b| {
        b.iter_batched(
            || {
                let mut issuer = Issuer::new();
                let published = issuer.public_key();
                let (state, blinded) = blind();
                let issued = mint(&mut issuer, blinded);
                (state, issued, published)
            },
            // `unblind` verifies the issuer's proof before accepting.
            |(state, issued, published)| black_box(unblind(state, issued, published).unwrap()),
            BatchSize::SmallInput,
        )
    });

    let mut issuer = Issuer::new();
    let published = issuer.public_key();
    let (state, blinded) = blind();
    let issued = mint(&mut issuer, blinded);
    let token = unblind(state, issued, published).unwrap();
    g.bench_function("verify", |b| {
        b.iter(|| black_box(issuer.verify(black_box(&token))))
    });

    g.finish();
}

/// Proof-of-work: `solve` (what a client pays, brute force) across difficulties, and
/// `verify` (what the server pays — a single hash). The asymmetry is the point.
fn pow(c: &mut Criterion) {
    let challenge = [0x11u8; 32];
    let mut g = c.benchmark_group("pow");

    for bits in [8u32, 12, 16] {
        g.bench_with_input(BenchmarkId::new("solve", bits), &bits, |b, &bits| {
            b.iter(|| black_box(Sha256Pow.solve(black_box(&challenge), bits)))
        });
    }

    let proof = Sha256Pow.solve(&challenge, 16);
    g.bench_function("verify", |b| {
        b.iter(|| black_box(Sha256Pow.verify(black_box(&challenge), black_box(&proof), 16)))
    });

    g.finish();
}

criterion_group!(benches, voprf, pow);
criterion_main!(benches);
