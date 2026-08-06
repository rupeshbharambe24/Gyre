# Gyre — Primitive Benchmarks

![status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)
![bench: criterion](https://img.shields.io/badge/bench-criterion-informational.svg)
![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Reproducible microbenchmarks of Gyre's building-block primitives, measured with
[criterion](https://github.com/bheisler/criterion.rs) (statistical benchmarking with
confidence intervals). They live in the [`gyre-benches`](crates/gyre-benches) crate.

> [!IMPORTANT]
> **What these measure — and what they do not.** These are *microbenchmarks of the
> primitives* (onion wrap/unwrap, Reed–Solomon coding, the VOPRF token, proof-of-work,
> the key ratchet, PIR, steganography) run **in isolation on a single core**. They show
> the primitives are fast enough to be viable and let us catch performance regressions.
>
> They are **not** an end-to-end measurement. They say **nothing** about real network
> latency, throughput under load, anonymity, or how Gyre compares to Tor or Nym — those
> require a simulated or real multi-node network (Shadow / NetEm), a separate effort in
> [`docs/ROADMAP.md`](docs/ROADMAP.md). Do not read any number here as a competitive claim.

## How to reproduce

```bash
# Full run (default criterion settings — tightest confidence intervals)
cargo bench -p gyre-benches

# Quick run (what produced the numbers below)
cargo bench -p gyre-benches -- --sample-size 20 --measurement-time 3 --warm-up-time 1
```

## Environment

| | |
|---|---|
| CPU | Apple M5 (10 cores) |
| OS | macOS 26.5.2 |
| Toolchain | rustc 1.96.0, `--release` bench profile (opt-level 3, `lto = "thin"`) |
| Harness | criterion 0.5.1, single bench thread |
| Settings | `--sample-size 20 --measurement-time 3 --warm-up-time 1` (quick run) |

Absolute numbers are hardware-specific; the **orders of magnitude and the ratios**
(e.g. PoW solve-vs-verify asymmetry) are what carry across machines. Reported times are
the criterion point estimate (median of the confidence interval).

## Results

### Sphinx onion (outbound data plane)

Fixed-size packet, 3-hop route. `wrap` builds a full 3-layer onion; `process` peels one
layer at one relay.

| Operation | Time | Rate (1 core) |
|---|---:|---:|
| `wrap` (build 3-hop onion) | 142 µs | ~7,000 packets/s |
| `process` (peel one hop) | 44.6 µs | ~22,400 hops/s |

### Reed–Solomon erasure coding (the novel core)

64 KiB message, two `data + parity` shapes. `reassemble` includes the Reed–Solomon
*reconstruction* from the minimum shard set (not a trivial concatenation).

| Shape | `encode` | throughput | `reassemble` | throughput |
|---|---:|---:|---:|---:|
| 4 + 2 | 36.3 µs | 1.68 GiB/s | 38.1 µs | 1.60 GiB/s |
| 10 + 4 | 77.1 µs | 811 MiB/s | 81.6 µs | 766 MiB/s |

### VOPRF capability token (inbound admission)

RFC 9497 `ristretto255-SHA512`, via the audited [`voprf`](https://crates.io/crates/voprf)
crate. One full unlinkable issue→redeem path is the four stages below.

| Stage | Who | Time |
|---|---|---:|
| `blind` | client | 25.1 µs |
| `issue` (blind-evaluate **+ DLEQ proof**) | issuer | 107.5 µs |
| `unblind` (**verify proof** + finalize) | client | 150.4 µs |
| `verify` (redemption) | issuer | 24.5 µs |

> [!IMPORTANT]
> **These numbers went up, and that is the point.** An earlier measurement reported `issue`
> at 23 µs and `unblind` at 30 µs. That version carried **no DLEQ proof** — a flaw that
> broke unlinkability outright (see [`docs/AUDIT.md`](docs/AUDIT.md)). Issuance now
> generates a proof and unblinding *verifies* it, which is where the extra ~85 µs and
> ~120 µs go. The old figures measured a construction that did not do its job; comparing
> against them would be comparing against a bug.
>
> In absolute terms the whole issue→redeem path is well under a millisecond, so the
> correctness is essentially free at any realistic admission rate.

### Proof-of-work admission (inbound)

SHA-256 leading-zero-bit puzzle. The design point is the **asymmetry**: the client pays
`solve`, the server pays a single-hash `verify`.

| Operation | Time |
|---|---:|
| `solve` @ 16 bits (client) | 3.52 ms |
| `verify` (server, one hash) | 15.0 ns |
| **asymmetry @ 16 bits** | **~230,000×** |

> [!NOTE]
> `solve` is **probabilistic and challenge-dependent** — it brute-forces the first
> qualifying nonce, so any single challenge's solve time is a sample, not the mean. The
> honest reading is the *shape*: `verify` is a fixed single hash while `solve` cost grows
> exponentially with the difficulty bits (`difficulty_for_load` raises the bits under
> flood). Low-difficulty single-challenge samples (8/12-bit ≈ 10 µs here) are not
> representative of average-case work and are omitted for that reason.

### Hardening primitives

| Primitive | Operation | Time | Throughput |
|---|---|---:|---:|
| Forward-secret ratchet (`gyre-endpoint`) | `next_message_key` | 193 ns | ~5.2M steps/s |
| 2-server IT-PIR (`gyre-pir`), 256 × 1 KiB | `answer` (one server) | 1.84 µs | 133 GiB/s |
| 2-server IT-PIR | `recover` (client XOR) | 32 ns | — |
| LSB steganography (`gyre-stego`), 64 KiB cover | `embed` | 2.57 µs | 23.7 GiB/s |
| LSB steganography | `extract` | 1.92 µs | 31.8 GiB/s |

## Reading the results

- **The data plane is not the bottleneck.** Onion and Reed–Solomon work is microseconds
  per packet/message on one core; a real deployment's cost is dominated by network RTT
  and the *deliberate* mixing delay (FAST/MIX lanes), not by these primitives.
- **Admission crypto is cheap for the server, dear for the attacker.** A token `verify`
  and a PoW `verify` are tens of nanoseconds to tens of microseconds, while a PoW `solve`
  scales exponentially with difficulty — the intended cost asymmetry.
- **These are floors, not ceilings, and not the point.** The number that actually decides
  whether Gyre works — end-to-end anonymity against a real adversary, at scale, with a
  crowd — is **not** on this page and cannot be, until the Shadow simulation is built.
