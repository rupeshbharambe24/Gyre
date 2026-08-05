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
- [x] **S1 — networked relays.** Each relay is now an async server: an onion really
  travels client → relay → relay → exit → destination over the network, resolving
  next hops through a directory. (Transport is length-prefixed frames over async
  TCP for now; the QUIC/MASQUE upgrade is a later milestone.)
- [ ] S2 — per-hop Poisson mixing + cover loops
- [ ] S3 — erasure-coded multipath (the novel core)
- [ ] S4 — FAST / MIX adaptive lanes
- [ ] GATE — adversary-emulation harness: measure correlation vs. a baseline
- [ ] S5 — QUIC/MASQUE transport upgrade, then the inbound rotor

## Quickstart

```bash
# Run the S1 demo: route a Sphinx onion across a localhost testnet of relays
cargo run -p whirl-node

# Tests, format, lint
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Example S1 output:

```text
Whirlpool · S1 — Sphinx onion over the network  (3 hops, lane=fast)
relay #1  listening on 127.0.0.1:63771
relay #2  listening on 127.0.0.1:63772
relay #3  listening on 127.0.0.1:63773
dest  #42 listening on 127.0.0.1:63774
client  wrap 51 bytes -> send to first hop 127.0.0.1:63771
[relay #1] forward -> #2
[relay #2] forward -> #3
[relay #3] EXIT -> deliver 51 bytes to dest #42
delivered: "hello from the client, across the whirlpool network"
OK  onion crossed 3 networked hops; no relay saw both ends.
```

## Layout

| Crate | What it holds |
|---|---|
| `whirl-common` | Shared constants and types (e.g. `FlowClass`) |
| `whirl-sphinx` | Typed wrapper over the audited Sphinx mix-packet format |
| `whirl-net` | Async transport, directory, and relay server (carries onions over the wire) |
| `whirl-node` | Demo: spin up a testnet and route an onion across it |

## Design principle

**Never roll your own crypto or transport.** The risky parts are audited crates
we integrate, not code we invent. The value is in combining known-good primitives
well and measuring honestly — see [`docs/DESIGN.md`](docs/DESIGN.md).

## License

[MIT](LICENSE).
