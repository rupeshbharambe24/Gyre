//! Inbound-admission crypto benchmarks: the blind VOPRF capability-token stages and
//! the proof-of-work puzzle (client `solve` cost vs. server `verify` cost).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use gyre_shield::token::{blind, unblind, Issuer};
use gyre_shield::Puzzle;

/// The four VOPRF stages: client `blind`, issuer `issue`, client `unblind`, issuer
/// `verify`. Each is a small number of ristretto scalar multiplications.
fn voprf(c: &mut Criterion) {
    let issuer = Issuer::new();
    let mut g = c.benchmark_group("voprf_token");

    g.bench_function("blind", |b| b.iter(|| black_box(blind())));

    let published = issuer.public_key();
    let (_state, blinded) = blind();
    // `issue` now also produces a DLEQ proof — that cost is part of issuance.
    g.bench_function("issue", |b| {
        b.iter(|| black_box(issuer.issue(black_box(blinded)).unwrap()))
    });

    g.bench_function("unblind", |b| {
        b.iter_batched(
            || {
                let (state, blinded) = blind();
                let issued = issuer.issue(blinded).unwrap();
                (state, issued)
            },
            // `unblind` now verifies the issuer's proof before accepting.
            |(state, issued)| black_box(unblind(state, issued, published).unwrap()),
            BatchSize::SmallInput,
        )
    });

    let (state, blinded) = blind();
    let issued = issuer.issue(blinded).unwrap();
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
            let puzzle = Puzzle::new(challenge, bits);
            b.iter(|| black_box(puzzle.solve()))
        });
    }

    let puzzle = Puzzle::new(challenge, 16);
    let nonce = puzzle.solve().nonce;
    g.bench_function("verify", |b| {
        b.iter(|| black_box(puzzle.verify(black_box(nonce))))
    });

    g.finish();
}

criterion_group!(benches, voprf, pow);
criterion_main!(benches);
