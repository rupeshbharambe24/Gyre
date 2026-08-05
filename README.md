# Whirlpool

**A layered privacy-and-defense network fabric.** One fabric, two rotors: an
outbound *mixer* that dissolves a person into a crowd, and an inbound *shield*
that hides and protects a system.

> ⚠️ **Status: early research / experimental. Unaudited. Do not rely on it for
> real anonymity or safety yet.** This repository is being built in the open,
> milestone by milestone, and every claim is measured before it is trusted.

## What it is (honestly)

Whirlpool is **not** a magic anonymity box, and it cannot beat physics:

- It cannot beat a global passive observer at low latency.
- It cannot manufacture anonymity without a crowd — anonymity *is* the size of
  the concurrent anonymity set.
- It respects the anonymity trilemma: strong anonymity, low latency, and low
  overhead cannot all hold at once.

What it *can* be is a **well-integrated** fabric built from audited, known-good
primitives, tuned for a **named adversary** (a *partial* network observer + a
censoring ISP + Sybil relay operators), with one thing no anonymity network
offers alongside a competitive outbound rotor: an **inbound server-protection
rotor**. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full picture and the
honest ceilings.

## The two rotors

- **Outbound — protect a person.** Sphinx onion routing, per-hop Poisson mixing,
  Loopix cover traffic, erasure-coded multipath, and adaptive FAST/MIX lanes.
- **Inbound — protect a system.** Rendezvous origin-hiding, moving-target-defense
  address hopping, proof-of-work admission, and unlinkable capability tokens.

## Where we are

The build is measurement-gated: each step ends with a number against a baseline.

- [x] **S0 — Sphinx onion echo.** A payload is wrapped and processed hop-by-hop so
  that no relay sees both ends and the exit recovers the exact payload. Built on
  the audited [`sphinx-packet`](https://crates.io/crates/sphinx-packet) crate.
- [ ] S1 — QUIC/MASQUE transport + the adversary-emulation harness (the go/no-go gate)
- [ ] S2 — per-hop Poisson mixing + cover loops
- [ ] S3 — erasure-coded multipath (the novel core)
- [ ] S4 — FAST / MIX adaptive lanes
- [ ] … inbound rotor, then the orthogonal hardening layers

## Quickstart

```bash
# Run the S0 demo: echo a Sphinx onion through a 3-hop circuit
cargo run -p whirl-node

# Tests, format, lint
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Example S0 output:

```text
Whirlpool · S0 — Sphinx onion echo  (3 hops, lane=fast)
client  wrapping 44 bytes for a 3-hop route -> exit delivers to dest #42
  hop 1  relay #1   forward -> #2    (delay 0ns; learns nothing else)
  hop 2  relay #2   forward -> #3    (delay 0ns; learns nothing else)
  hop 3  relay #3   EXIT    -> deliver to dest #42
OK  no hop saw both ends; the exit recovered the exact payload.
```

## Layout

| Crate | What it holds |
|---|---|
| `whirl-common` | Shared constants and types (e.g. `FlowClass`) |
| `whirl-sphinx` | S0 — typed wrapper over the audited Sphinx mix-packet format |
| `whirl-node` | S0 demo: build an onion and echo it through a circuit |

## Design principle

**Never roll your own crypto or transport.** The risky parts are audited crates
we integrate, not code we invent. The value is in combining known-good primitives
well and measuring honestly — see [`docs/DESIGN.md`](docs/DESIGN.md).

## License

[MIT](LICENSE).
