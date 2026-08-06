//! Hardening-primitive benchmarks: the forward-secret key ratchet, 2-server PIR, and
//! LSB steganography.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use gyre_endpoint::Ratchet;
use gyre_pir::{build_queries, recover, Directory};
use gyre_stego::{embed, extract};

/// One forward-secret ratchet step (derive a message key + advance the chain).
fn ratchet(c: &mut Criterion) {
    let mut r = Ratchet::new([0x42u8; 32]);
    c.bench_function("ratchet/next_message_key", |b| {
        b.iter(|| black_box(r.next_message_key()))
    });
}

/// 2-server IT-PIR over a directory of 256 × 1 KiB records: `answer` (a server XORs
/// the selected records) and `recover` (the client XORs the two answers).
fn pir(c: &mut Criterion) {
    let (n, l) = (256usize, 1024usize);
    let records: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; l]).collect();
    let dir = Directory::new(records);
    let (qa, qb) = build_queries(n, 42);

    let mut g = c.benchmark_group("pir");
    g.throughput(Throughput::Bytes((n * l) as u64));
    g.bench_function("answer", |b| {
        b.iter(|| black_box(dir.answer(black_box(&qa))))
    });

    let a = dir.answer(&qa);
    let bb = dir.answer(&qb);
    g.throughput(Throughput::Bytes(l as u64));
    g.bench_function("recover", |b| {
        b.iter(|| black_box(recover(black_box(&a), black_box(&bb))))
    });
    g.finish();
}

/// LSB steganography over a 64 KiB cover carrying a 1 KiB secret: `embed` and
/// `extract`. Throughput is reported in bytes of cover scanned.
fn stego(c: &mut Criterion) {
    let cover = vec![0x80u8; 64 * 1024];
    let secret = vec![0x5Au8; 1024];

    let mut g = c.benchmark_group("stego");
    g.throughput(Throughput::Bytes(cover.len() as u64));
    g.bench_function("embed", |b| {
        b.iter(|| black_box(embed(black_box(&cover), black_box(&secret)).unwrap()))
    });

    let carrier = embed(&cover, &secret).unwrap();
    g.throughput(Throughput::Bytes(carrier.len() as u64));
    g.bench_function("extract", |b| {
        b.iter(|| black_box(extract(black_box(&carrier)).unwrap()))
    });
    g.finish();
}

criterion_group!(benches, ratchet, pir, stego);
criterion_main!(benches);
