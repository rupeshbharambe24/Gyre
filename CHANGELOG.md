# Changelog

All notable changes to **Gyre** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

![Status](https://img.shields.io/badge/status-experimental-orange.svg)
![Version](https://img.shields.io/badge/version-0.0.1-lightgrey.svg)
![Release](https://img.shields.io/badge/release-none%20tagged-inactive.svg)
![Audit](https://img.shields.io/badge/audit-unaudited-red.svg)
![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)
![Crates](https://img.shields.io/badge/crates-14-informational.svg)
![Tests](https://img.shields.io/badge/tests-157%20green-success.svg)
[![CI](https://github.com/rupeshbharambe24/Gyre/actions/workflows/ci.yml/badge.svg)](https://github.com/rupeshbharambe24/Gyre/actions/workflows/ci.yml)

> [!NOTE]
> This is a **pre-1.0 research build**. No version has been **tagged or released**,
> and nothing is **published to crates.io**. Under SemVer, `0.y.z` is initial
> development: anything may change at any time, and the public API is not stable.
> The current workspace version is `0.0.1`.

> [!WARNING]
> Gyre is **early-stage and UNAUDITED**. Do **not** rely on it for real
> anonymity or safety yet. Every claim here is *measured before it is trusted*,
> and the honest ceilings live inline with the entries that earn them — not at the
> bottom. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full threat model.

---

## Contents

- [Unreleased](#unreleased)
  - [Milestone status](#milestone-status)
  - [Added](#added)
  - [Fixed](#fixed)
  - [Deferred](#deferred-not-a-keep-a-changelog-category)
- [About versioning](#about-versioning)

---

## [Unreleased]

Gyre has been built **milestone by milestone**, entirely in the open. The
build history below is the real thing — a layered privacy-and-defense fabric with
**two rotors**: an *outbound* mixer that dissolves a person into a crowd, and an
*inbound* shield that hides and protects a system.

```mermaid
flowchart LR
  subgraph P0["Outbound data plane (P0)"]
    S0["S0 Sphinx echo"] --> S1["S1 networked relays"] --> S2["S2 mixing + cover"] --> S3["S3 erasure-multipath"] --> S4["S4 FAST / MIX lanes"]
  end
  S4 --> GATE["GATE: adversary harness"]
  GATE --> IN["Inbound rotor: MTD + PoW + rendezvous + VOPRF tokens"]
  IN --> P3["P3: six orthogonal hardenings"]
  P3 --> P4["P4: crowd / incentive layer"]
```

### Milestone status

- [x] **P0** outbound data plane (S0 → S4)
- [x] **GATE** partial-observer correlation harness (go/no-go)
- [x] **Inbound rotor** — MTD, PoW admission, rendezvous, VOPRF tokens
- [x] **P3** hardening — all six orthogonal additions
- [x] **P4** crowd / incentive layer
- [ ] **S5** QUIC/MASQUE transport swap — *deferred* (see below)

### Added

Entries are listed in the order they were built. Each capability claim carries its
honest ceiling inline, wherever one applies.

**P0 — Outbound data plane (protect a person)**

- **S0 — Sphinx onion echo.** `gyre-sphinx`, a typed wrapper over the audited
  `sphinx-packet` mix-packet format, with end-to-end onion encrypt/echo. Shared
  constants and types land in `gyre-common` (`FlowClass`, `DEFAULT_HOPS = 3`).
- **S1 — Networked relays.** `gyre-net` async transport, directory, and relay
  server carry the Sphinx onion over the wire (TCP length-prefixed frames). No
  single relay learns both ends; the onion is capped at 3 hops (D5).
- **S2 — Mixing + cover.** Per-hop Poisson mixing and Loopix shared cover traffic
  in `gyre-net`.
  *Ceiling:* Loopix global-observer resistance holds **only at mix latency**,
  never at low latency.
- **S3 — Erasure-coded multipath.** `gyre-fec` Reed–Solomon fragmentation and
  reassembly across paths.
  *Ceiling (D7):* this is **probabilistic middle-path hardening** against a
  *partial* observer — **not** a reconstruction threshold. Endpoints stay exposed,
  and spreading a message over more paths *widens* what a partial observer touches
  (measured under the GATE). It buys availability and content-splitting, not
  correlation resistance.
- **S4 — FAST / MIX adaptive lanes.** Per-flow choice between a low-latency **FAST**
  lane and a mixing **MIX** lane, sealed inside the onion (D8). The `gyre-node`
  demo spins up a testnet and times both lanes on the same route.

**The GATE (the go/no-go)**

- **GATE — adversary-emulation harness.** `gyre-adversary`, a partial-observer
  timing-correlation harness that emits a verdict. It is the instrument every
  later claim is checked against.
  <details>
  <summary>Measured verdict (quoted from the harness)</summary>

  | flows | window | mix/hop | accuracy | chance | note |
  |------:|-------:|--------:|---------:|-------:|------|
  | 50 | 1000ms | 0ms | 1.00 | 0.02 | baseline: no mixing (FAST lane) |
  | 50 | 1000ms | 50ms | 0.11 | 0.02 | MIX lane, healthy crowd |
  | 50 | 1000ms | 150ms | 0.04 | 0.02 | more mixing |
  | 5 | 1000ms | 150ms | 0.44 | 0.20 | same mixing, tiny crowd → barely helps |

  Multipath exposure — fraction of flows a partial observer on 20% of paths
  touches: single-path (k=1) `0.23`, multipath (k=3) `0.56`.

  **Verdict:** (1) mixing works and is the real correlation-resistance lever
  (`1.00` → near chance); (2) it is **gated on the crowd** (tiny crowd `0.44` —
  cleverness never manufactures anonymity); (3) multipath does **not** buy
  partial-observer correlation resistance — it *widens* exposure (`0.23` → `0.56`).
  </details>

**Inbound rotor (protect a system)**

- **MTD ingress hopping + PoW admission.** `gyre-shield` moving-target-defense
  address hopping via `HMAC(key, time_window)`, plus proof-of-work admission.
  *Ceiling (D2):* rotation is **defense, not anonymity**.
- **Rendezvous origin-hiding.** Rendezvous-based origin hiding for the protected
  asset, so the origin never faces clients directly.
- **VOPRF capability tokens.** Unlinkable capability tokens (blind *verifiable* OPRF,
  RFC 9497 *shape*) complete the inbound rotor. The issuer attaches a **DLEQ proof** that
  it used its published key; the client refuses the token otherwise.
  *Ceiling:* this is a **hand-built PROTOTYPE** on `curve25519-dalek` primitives
  and is **UNAUDITED** — the prepared audit package is [`docs/AUDIT.md`](docs/AUDIT.md).
  Anonymous credentials add **zero** intrinsic Sybil resistance — only the scarce
  resource (PoW / stake) does.

**P3 — Six orthogonal hardening additions** (added *by threat*, not by default;
a matrix, not a stack — D10). Shipped in landing order 1, 2, 4, 6, 5; Addition 3
(anonymous credentials) had already shipped as the VOPRF token above.

- **Addition 1 — Obfuscation / pluggable transports.** `gyre-obfs`: a
  pluggable-transport framework, transports, and an entropy meter.
  *Ceiling:* appearance only, **zero anonymity effect**. "Unblockable" is not
  claimed — obfuscation only makes blocking *more expensive than a censor will pay
  today*, and random-byte transports are themselves a positive entropy-DPI
  fingerprint.
- **Addition 2 — Endpoint hardening + data minimization.** `gyre-endpoint`:
  forward-secret ratchet, personas, uniform fingerprint.
  *Ceiling:* endpoint compromise (a login, a device, a fingerprint) deanonymises
  regardless of the network.
- **Addition 4 — Decentralization + attestation.** `gyre-directory`:
  threshold-signed consensus, equivocation detection, build attestation.
  *Ceiling:* **detection, not prevention** — reproducible builds prove
  *binary == source*, not that a relay actually runs that binary.
- **Addition 6 — Private directory retrieval.** `gyre-pir`: 2-server IT-PIR.
  *Ceiling:* **default OFF** — a full signed directory download is leak-free and
  cheaper; PIR is surgical, not the default path (D18).
- **Addition 5 — Deniability / steganography.** `gyre-stego`: LSB steganography.
  *Ceiling:* **situational** — LSB stego is trivially detectable.

**P4 — Crowd / incentive layer**

- **Crowd admission + Sybil pricing.** `gyre-crowd`: a k-anonymity admission
  governor and a staking Sybil-pricing model.
  *Ceiling:* the crowd is the binding constraint everywhere (D12, D20). Staking is
  **wealth concentration, not user-decentralization**, and adds no intrinsic Sybil
  resistance on its own.

**Tooling & quality gates**

- **Workspace.** 14 crates, 157 tests, all green. See [`README.md`](README.md) and
  [`docs/DESIGN.md`](docs/DESIGN.md).
- **Gates.** `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, and `cargo test --workspace`. CI runs all three
  on every pull request and on pushes to `main`.
- **Q4 — consensus-pinned issuer key (completes the token fix).** The DLEQ proof is only
  worth anything if the key it is checked against did not come from the issuer, so the
  consensus body is now a **typed, canonically encoded** `NetworkParams` document
  (`gyre-directory::params`) carrying the issuer public key, PoW difficulty, MTD window and
  relay set. Decoding is strict — exact length, known magic and version, **no trailing
  bytes** — so each document has exactly one valid encoding; a lenient parser would let a
  signature over one byte string appear to cover another. `VerifiedParams` can be produced
  **only** by `verify_consensus` (non-zero threshold, enough distinct valid signatures,
  well-formed body, and the body's epoch bound to the envelope), and
  `token::PublicKey::from_verified_params` is the blessed way to obtain a key. The
  unverified path survives for tests but is named `from_unverified_bytes` so a grep finds
  every place trust was assumed. End-to-end coverage in
  `crates/gyre-shield/tests/consensus_pinned_key.rs`, including the full attack: a rogue
  issuer with an internally valid proof for *its own* key is refused.
- **Cryptographic audit package** ([`docs/AUDIT.md`](docs/AUDIT.md)) for the one hand-built
  construction: full specification, security model with the four claimed properties,
  a table of every deviation from RFC 9497, seven self-review findings (one critical, see
  *Fixed*), six ranked open questions for an auditor, and reproducible test vectors
  (`cargo test -p gyre-shield --test token_vectors`). Also adds
  `Issuer::from_secret_seed` so an operator can reload a key across restarts — without it,
  every restart silently invalidated outstanding tokens.
- **Simulation harness (`gyre-sim`) — the GATE, run against the real code.** A
  discrete-event simulator that drives the **actual** protocol implementation (real Sphinx
  onions, real X25519 relay keys, the real Loopix delay sampler, real packet sizes) over a
  modelled network, and attacks it with the **strongest matcher we can construct**:
  a maximum-likelihood (Erlang) cost solved **optimally** by the Hungarian algorithm
  (verified against brute force for `n ≤ 6`). Flows are multi-packet circuits, because
  single-message flows understate stream correlation. Reports coverage, accuracy, the
  end-to-end **deanonymisation rate** (`coverage × accuracy`), latency percentiles, and
  wire overhead. Run with `cargo run --release -p gyre-sim`; full write-up in
  [`docs/SIMULATION.md`](docs/SIMULATION.md).
- **Shadow scaffolding** (`sim/shadow/`) for the Linux-only next step — explicitly marked
  **not yet executed**, since Shadow cannot run on the machine used here.
- **Property-based test suite (proptest).** `crates/*/tests/properties.rs` adds **52
  properties** across ten crates, each generating hundreds of inputs per run and shrinking
  any failure to a minimal counterexample. They assert the domain invariants (any `data`
  of `data + parity` fragments reconstruct the message; a solved PoW puzzle always
  verifies; the MTD ingress is deterministic and always a real candidate; acceptance
  tracks the *distinct* signer count; the admission governor is monotone in the crowd) and
  a **"parsing arbitrary bytes never panics"** property for every parser that reads
  untrusted input — fuzz-like coverage that runs on stable in CI. Test count: 55 → **108**.
- **Fuzzing targets (cargo-fuzz).** `fuzz/fuzz_targets/` covers the Sphinx packet parser,
  the FEC fragment parser and reassembler, LSB extraction, every pluggable transport's
  de-obfuscation path, and the capability-token issuer. `fuzz/` is its own workspace and
  is excluded from the root one, so the stable toolchain CI uses never builds it; running
  the targets needs nightly plus `cargo install cargo-fuzz` (see `CONTRIBUTING.md`).
- **Primitive benchmark suite.** A dev-only `gyre-benches` crate (criterion)
  microbenchmarks the building blocks — onion wrap/unwrap, Reed–Solomon coding, the
  VOPRF token stages, proof-of-work solve/verify, the key ratchet, PIR, and
  steganography — with results and honest caveats in [`BENCHMARKS.md`](BENCHMARKS.md).
  These measure the primitives in isolation, **not** end-to-end anonymity or latency.
  Run with `cargo bench -p gyre-benches`.
- **Integration hygiene (D11).** Cryptography and transport are built on audited,
  known-good crates (`sphinx-packet`, `x25519-dalek`, `curve25519-dalek`,
  `ed25519-dalek`, `reed-solomon-erasure`, `hmac`, `sha2`, `zeroize`, `tokio`)
  rather than rolled from scratch. The VOPRF token construction is the one
  exception — hand-built on those audited `curve25519-dalek` primitives — and it is
  flagged as an unaudited prototype above.

### Fixed

- **CRITICAL — the capability token's unlinkability was completely broken.** The
  construction was documented as a "blind **V**OPRF (RFC 9497 shape)" but shipped **no DLEQ
  proof**, making it the *base* OPRF mode. That enables textbook **key partitioning**: a
  malicious issuer hands each client a different secret key, then at redemption tries every
  key — exactly one verifies, identifying the issuance session and therefore the client. A
  proof-of-concept **linked 5 of 5 redemptions**; the property the token exists to provide
  was absent, not merely unproven. **Fixed** by implementing the Chaum–Pedersen DLEQ proof:
  the issuer must prove it used the key behind its published public key, and `unblind` now
  refuses the token otherwise (`unblind` takes the pinned public key as a third argument).
  The same attack now links **0 of 5** — retained as a regression test in
  `crates/gyre-shield/tests/token_unlinkability.rs`. Full analysis in
  [`docs/AUDIT.md`](docs/AUDIT.md).
  > **Deployment caveat:** the fix only holds if clients pin the public key from the
  > threshold-signed consensus. That wiring is **not yet implemented** and is tracked as
  > open question Q4 in the audit package.
- **HIGH — `accept_consensus` accepted unsigned documents at threshold 0.** The check was
  `distinct_valid_signers(...) >= threshold`, which is **always true** for `threshold == 0`
  — so a caller deriving its threshold from configuration (an empty authority list gives
  `0`) would accept a completely unsigned consensus, and with it any issuer key an attacker
  chose. Confirmed by probe before fixing. Both `accept_consensus` and `verify_consensus`
  now reject a zero threshold outright: trust decisions fail closed. A property asserts it
  for arbitrary signature sets.
- **Token secrets are now zeroized.** `Blinding.blind` — the scalar whose secrecy *is*
  unlinkability — and `Issuer.key` were left in memory on drop, inconsistent with
  `gyre-endpoint`. Both are now `ZeroizeOnDrop`, along with intermediate hash buffers.
- **The double-spend set can now be bounded.** It grew without limit (a memory-exhaustion
  DoS); `Issuer::rotate()` starts a new epoch — fresh key, cleared set — and
  `spent_count()` makes the size observable. Rotation is operator policy, so the residual
  risk is documented rather than closed.
- **Hash-input ambiguity removed.** `hash_to_point` took `&[u8]`, so `DST ‖ seed` would be
  ambiguous for variable-length seeds. Latent (all callers passed 32 bytes), now impossible
  by type.
- **Corrected an overclaim in the GATE's own documentation, and the numbers it produced.**
  `gyre-adversary` described its greedy matcher as chosen "so anonymity never looks better
  than it is" — exactly backwards. A *weaker* attacker makes anonymity look **better**, so
  the published figures were optimistic. Combined with modelling each flow as a single
  message rather than a stream, the MIX lane at 50 ms/hop was reported as `0.11` where the
  real code under an optimal attacker scores **≈ 0.50** — about **4.5×** off. The GATE is
  retained as a fast regression signal, its docs corrected, and every place quoting its
  numbers now carries the correction and points at
  [`docs/SIMULATION.md`](docs/SIMULATION.md).
- **`gyre-sphinx` now re-exports `SphinxPacket`.** The type appears throughout the crate's
  public API, but was not nameable downstream — so a caller could not hold a packet in a
  struct or queue without adding its own `sphinx-packet` dependency, defeating the wrapper's
  purpose (**D11**). Found while building the simulation harness, which needs exactly that.

The two below were found by the property suite, not by review — which is rather the
point of adding it.

- **Admission control could fail open on a bad load estimate** (`gyre-shield`).
  `difficulty_for_load` took an `f64` load ratio; `f64::clamp` propagates `NaN` and
  `NaN as u32` saturates to `0`, so a `NaN` load — which a real estimator produces from
  `0.0 / 0.0` on a reset counter or stalled sampler — yielded a **zero-bit puzzle, i.e.
  free admission**, precisely when the estimator was broken. Non-finite loads are now
  treated as unknown and charged the base cost; the difficulty is now provably within
  `[8, 20]` for **every** `f64`. Guarded by both a deterministic regression test and a
  property, each verified to fail without the fix.
- **`capacity_bytes` was not a usable "will it fit?" predicate** (`gyre-stego`). It
  returns `0` both for a cover that can carry an empty message and for one too small to
  carry anything at all, and the 32-byte header constant it depends on was private — so a
  caller could not express `embed`'s real precondition. Added `fits(cover_len,
  secret_len)`, which is exactly that precondition, made `embed` use it as the single
  source of truth, and exported `LENGTH_HEADER_BITS`. (Found by proptest shrinking to
  `cover = [], secret = []`.)

### Deferred (not a Keep a Changelog category)

- **S5 — QUIC/MASQUE transport swap.** Deferred as low-value, high-risk plumbing.
  TCP length-prefixed frames work today, and the swap has **no bearing on the
  anonymity properties**. This is the only outstanding milestone item.

---

## About versioning

No release has been cut. When one is, it will appear here as a dated
`## [x.y.z]` heading above **Unreleased**, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Because this is a 2026
research build and precise per-commit dates are not part of this record, entries
are undated (or attributed to **2026**) rather than assigned specific days.

Gyre's whole identity is refusing to overclaim. The recurring lesson across
every milestone above is the same one the GATE measured: **anonymity is the size
of the concurrent crowd**, and no amount of engineering manufactures it.
