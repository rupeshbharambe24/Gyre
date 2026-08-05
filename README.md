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
- [x] **GATE — adversary-emulation harness.** A deterministic timing model runs a
  *partial observer* correlation attack over many concurrent flows and measures it
  against a baseline. **This is the go/no-go, and the numbers are honest** (see below).
- [x] **Inbound shield (admission) — MTD hopping + PoW.** The other rotor. The public
  ingress is `HMAC(key, window)` so an authorized client and the origin agree while a
  scanner cannot pre-target it; proof-of-work admission scales its difficulty with load
  (server verifies in one hash). Honest ceiling (**D22**): MTD serves a *closed*,
  authorized client set (not the open web), and PoW re-prices asymmetry but does nothing
  for L3/L4 volumetric floods.
- [ ] Inbound shield (rest) — rendezvous origin-hiding + anonymous capability tokens
- [ ] S5 — QUIC/MASQUE transport upgrade (deferred: TCP framing works for now)

**P0 (the core data plane) is complete: S0 → S4, plus the measurement GATE. The
inbound rotor's admission layer (MTD + PoW) is in.**

## The GATE: what the measurement actually says

```text
 flows   window   mix/hop   accuracy   chance   note
   50    1000ms      0ms      1.00     0.02   baseline: no mixing (FAST lane)
   50    1000ms     50ms      0.11     0.02   MIX lane, healthy crowd
   50    1000ms    150ms      0.04     0.02   more mixing
    5    1000ms    150ms      0.44     0.20   same mixing, tiny crowd -> barely helps

multipath exposure — fraction of flows a partial observer (on 20% of paths) touches:
  single-path (k=1): 0.23
  multipath  (k=3): 0.56
```

The honest verdict this produces — and it matches the design analysis:

- **Mixing works, and it is the real correlation-resistance lever** — with no mixing a
  timing observer links flows *perfectly* (1.00); with MIX-lane delay it collapses to
  near chance.
- **But it is gated on the crowd.** The same mixing with only a handful of concurrent
  flows barely helps (0.44). Cleverness never manufactures anonymity — concurrent
  traffic does.
- **Multipath does *not* buy partial-observer correlation resistance** — it *widens*
  exposure (0.23 → 0.56). It buys availability and content-splitting, per **D7**.

## Quickstart

```bash
# Run the inbound-shield demo: MTD ingress hopping + PoW admission
cargo run -p whirl-shield

# Run the GATE report: the correlation sweep + multipath exposure
cargo run -p whirl-adversary

# Run the S4 demo: FAST vs MIX lanes on the same route, timed
cargo run -p whirl-node

# Tests, format, lint
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Layout

| Crate | What it holds |
|---|---|
| `whirl-common` | Shared constants and types (e.g. `FlowClass`) |
| `whirl-sphinx` | Typed wrapper over the audited Sphinx mix-packet format |
| `whirl-fec` | Reed–Solomon erasure coding: fragment a message, reassemble from any `m` |
| `whirl-net` | Async transport, directory, relay server, mixing, cover traffic |
| `whirl-node` | Demo: spin up a testnet and route traffic across it |
| `whirl-adversary` | The GATE: partial-observer correlation harness + measured verdict |
| `whirl-shield` | The inbound rotor: MTD ingress hopping + proof-of-work admission |

## Design principle

**Never roll your own crypto or transport.** The risky parts are audited crates
we integrate, not code we invent. The value is in combining known-good primitives
well and measuring honestly — see [`docs/DESIGN.md`](docs/DESIGN.md).

## License

[MIT](LICENSE).
