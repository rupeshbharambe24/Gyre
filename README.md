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
- [x] **S2 — mixing + cover traffic.** Each relay holds every packet for an
  independent exponential (Poisson) delay before forwarding, so packets can leave in
  a different order than they arrived; clients emit Loopix cover "loops" that are
  byte-for-byte indistinguishable on the wire from real traffic.
- [x] **S3 — erasure-coded multipath (the novel core).** A message is Reed–Solomon
  split into `m`-of-`k` fragments, each wrapped in its own onion and sent along a
  disjoint path; the destination reassembles from any `m`. Honest framing (**D7**):
  this hardens the *middle path* against a partial observer — it is **not** a
  reconstruction-threshold guarantee, and endpoints stay exposed.
- [x] **S4 — FAST / MIX adaptive lanes.** The client picks a per-flow tradeoff: FAST
  is onion-only (~zero added delay, Tor-class latency); MIX pays a Poisson per-hop
  delay for stronger timing resistance. The lane is never written in the clear —
  but note the honest ceiling (**D8**/**D21**): a partial observer can still separate
  the lanes by their observable delay distribution, so FAST and MIX partition the
  anonymity set rather than sharing one crowd.
- [ ] GATE — adversary-emulation harness: measure correlation vs. a baseline
- [ ] S5 — QUIC/MASQUE transport upgrade, then the inbound rotor

## Quickstart

```bash
# Run the S4 demo: FAST vs MIX lanes on the same route, timed
cargo run -p whirl-node

# Tests, format, lint
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Example S4 output (same 3-hop route; the lane only changes the delay policy):

```text
Whirlpool · S4 — FAST / MIX adaptive lanes  (3 hops)
FAST lane   mean/hop   0ms   ->   delivered in   15ms
 MIX lane   mean/hop  50ms   ->   delivered in  114ms
OK  same route, two lanes: FAST trades anonymity for latency, MIX the reverse.
```

## Layout

| Crate | What it holds |
|---|---|
| `whirl-common` | Shared constants and types (e.g. `FlowClass`) |
| `whirl-sphinx` | Typed wrapper over the audited Sphinx mix-packet format |
| `whirl-fec` | Reed–Solomon erasure coding: fragment a message, reassemble from any `m` |
| `whirl-net` | Async transport, directory, relay server, mixing, cover traffic |
| `whirl-node` | Demo: spin up a testnet and route traffic across it |

## Design principle

**Never roll your own crypto or transport.** The risky parts are audited crates
we integrate, not code we invent. The value is in combining known-good primitives
well and measuring honestly — see [`docs/DESIGN.md`](docs/DESIGN.md).

## License

[MIT](LICENSE).
