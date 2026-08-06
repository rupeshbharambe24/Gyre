//! Data-plane primitive benchmarks: the Sphinx onion and Reed–Solomon coding —
//! the two hottest paths a packet actually travels.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use gyre_fec::{encode, Reassembler};
use gyre_sphinx::{null_surb, wrap, Relay, ADDRESS_LEN, DEST_ADDRESS_LEN};

/// Onion `wrap` (build a 3-hop packet) and `process` (peel one layer at a relay).
fn sphinx(c: &mut Criterion) {
    let relays: Vec<Relay> = (1u8..=3).map(|i| Relay::new([i; ADDRESS_LEN])).collect();
    let route: Vec<_> = relays.iter().map(Relay::as_node).collect();
    let dest = [7u8; DEST_ADDRESS_LEN];
    let payload = vec![0xABu8; 64]; // Sphinx pads to a fixed size; content size is irrelevant.

    let mut g = c.benchmark_group("sphinx");
    g.bench_function("wrap_3hop", |b| {
        b.iter(|| wrap(black_box(&payload), black_box(&route), dest, null_surb()).unwrap())
    });
    // Fresh packet per iteration (process consumes it); setup cost is excluded.
    g.bench_function("process_one_hop", |b| {
        b.iter_batched(
            || wrap(&payload, &route, dest, null_surb()).unwrap(),
            |packet| black_box(relays[0].process(packet).unwrap()),
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

/// Reed–Solomon `encode` and reassembly-with-reconstruction over a 64 KiB message,
/// at two `data + parity` shapes. Throughput is reported in bytes of message.
fn fec(c: &mut Criterion) {
    let msg = vec![0x5Au8; 64 * 1024];
    let mut g = c.benchmark_group("fec");

    for (data, parity) in [(4usize, 2usize), (10usize, 4usize)] {
        let label = format!("{data}+{parity}");

        g.throughput(Throughput::Bytes(msg.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("encode", &label),
            &(data, parity),
            |b, &(d, p)| b.iter(|| encode(black_box(&msg), 0, d, p).unwrap()),
        );

        // Keep exactly `data` shards, skipping the first `parity` so reconstruction
        // must actually run Reed–Solomon (not just concatenate the data shards).
        let frags = encode(&msg, 0, data, parity).unwrap();
        let subset: Vec<_> = frags.into_iter().skip(parity).take(data).collect();

        g.throughput(Throughput::Bytes(msg.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("reassemble", &label),
            &subset,
            |b, subset| {
                b.iter_batched(
                    || subset.clone(),
                    |frags| {
                        let mut r = Reassembler::new();
                        let mut out = None;
                        for f in frags {
                            out = r.insert(f).unwrap();
                        }
                        black_box(out.unwrap())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    g.finish();
}

criterion_group!(benches, sphinx, fec);
criterion_main!(benches);
