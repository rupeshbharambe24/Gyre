# Contributing to Gyre

[![CI](https://github.com/rupeshbharambe24/Gyre/actions/workflows/ci.yml/badge.svg)](https://github.com/rupeshbharambe24/Gyre/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](Cargo.toml)
[![Crates](https://img.shields.io/badge/crates-15-blue.svg)](#the-workspace-at-a-glance)
[![Tests](https://img.shields.io/badge/tests-171%20green-brightgreen.svg)](#the-workspace-at-a-glance)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#project-ethos)

Thanks for your interest in **Gyre** — a layered privacy-and-defense network
fabric with two rotors: an **outbound mixer** that dissolves a person into a crowd,
and an **inbound shield** that hides and protects a system. This guide covers how we
build, what we measure, and the bar a change has to clear before it merges.

> [!IMPORTANT]
> Gyre is **early research and EXPERIMENTAL. It is UNAUDITED.** Do **not** rely
> on it for real anonymity or safety yet. Contributions are welcome precisely because
> the project is being built in the open, milestone by milestone — every claim is
> measured before it is trusted.

---

## Table of contents

1. [Project ethos](#project-ethos)
2. [The workspace at a glance](#the-workspace-at-a-glance)
3. [Prerequisites](#prerequisites)
4. [Local development](#local-development)
5. [Before you open a PR](#before-you-open-a-pr)
6. [How we test: unit, property, fuzz](#how-we-test-unit-property-fuzz)
7. [Adding a milestone or crate](#adding-a-milestone-or-crate)
8. [Commit & PR conventions](#commit--pr-conventions)
9. [Documentation changes](#documentation-changes)
10. [Code of Conduct](#code-of-conduct)
11. [License](#license)

---

## Project ethos

Three rules shape every contribution. They are not slogans — they are how we decide
whether a change is allowed in.

### 1. Measurement-gated

**Every step ends with a number against a baseline.** A feature is not "done" because
it compiles and the story sounds good; it is done when a test or a demo prints a
measurement that shows what it bought — and, just as importantly, what it did *not*.
The canonical example is the adversary harness (`gyre-adversary`, "THE GATE"): it
runs a partial-observer timing-correlation sweep and emits a verdict. Mixing takes an
attacker's correlation accuracy from `1.00` (no mixing) down toward chance — but only
in a healthy crowd. That number is the point, not the prose around it.

### 2. Never roll your own crypto or transport

**Integrate audited crates; do not reinvent primitives** (design decision **D11**).
Gyre is an *integration*, not a from-scratch cryptosystem. We build on top of:

| Concern | Crate we integrate |
| --- | --- |
| Sphinx mix-packet format | `sphinx-packet` 0.7.0 (Nym-audited) |
| X25519 / Curve25519 | `x25519-dalek` 3.0, `curve25519-dalek` 5 |
| Ed25519 signatures | `ed25519-dalek` 3 |
| Erasure coding | `reed-solomon-erasure` 6 |
| HMAC / hashing | `hmac` 0.13, `sha2` 0.11 |
| Secret hygiene | `zeroize` 1 (derive) |
| Async transport | `tokio` 1 |

> [!WARNING]
> The one hand-built cryptographic construction is the **VOPRF capability token** in
> `gyre-shield` — a prototype on `curve25519-dalek` primitives following the RFC 9497
> shape. It is **UNAUDITED**. Any doc, comment, or PR that mentions tokens must say so.

### 3. Honesty over hype

The project's whole identity is **refusing to overclaim**. Physics ceilings go
**in-line, next to the claim**, never buried in a footnote:

- Gyre **cannot** beat a **global passive observer** at low latency. Nobody can.
- Anonymity **is** the size of the concurrent anonymity set — cleverness never
  manufactures a crowd.
- The [anonymity trilemma](docs/DESIGN.md) is real: strong anonymity, low latency, low
  overhead — pick about two.
- **Endpoint compromise** (a login, a device, a fingerprint) deanonymises you
  regardless of what the network does.

Before you write a benchmark or a headline, read the anti-overclaim rules in
[docs/DESIGN.md § "What we can and cannot claim"](docs/DESIGN.md#7-what-we-can-and-cannot-claim).
They are project law.

---

## The workspace at a glance

Fifteen crates, **one crate per orthogonal concern**, 171 tests, all green.

| Crate | Purpose | Tests |
| --- | --- | :---: |
| `gyre-common` | shared constants & types (`FlowClass`, `DEFAULT_HOPS = 3`) | 3 |
| `gyre-sphinx` | typed wrapper over the audited Sphinx mix-packet format | 11 |
| `gyre-fec` | Reed-Solomon erasure coding: fragment a message, reassemble any *m* | 9 |
| `gyre-net` | async transport (TCP + QUIC), directory, relay server, mixing, cover traffic | 14 |
| `gyre-node` | demo binary: spin up a testnet + integration tests (lanes, multipath) | 2 |
| `gyre-adversary` | **THE GATE**: partial-observer timing-correlation harness + verdict | 4 |
| `gyre-shield` | inbound rotor: MTD hopping, PoW admission, rendezvous, capability tokens | 42 |
| `gyre-obfs` | pluggable-transport framework + transports + an entropy meter | 9 |
| `gyre-endpoint` | endpoint hardening: forward-secret ratchet, personas, uniform fingerprint | 8 |
| `gyre-directory` | threshold-signed consensus, typed params, equivocation detection, attestation | 21 |
| `gyre-pir` | private directory retrieval: 2-server IT-PIR (default is full download) | 6 |
| `gyre-stego` | deniability: LSB steganography (situational; honest limits) | 10 |
| `gyre-crowd` | k-anonymity admission governor + staking Sybil-pricing model | 8 |
| `gyre-sim` | simulation harness: real code, modelled network, optimal-assignment attacker | 19 |
| `gyre-cli` | standalone `gyre-relay` / `gyre-client` / `gyre-sink` binaries (real sockets) | 4 |
| **Total** | | **171** |

These three numbers — **15 crates / 171 tests / the GATE verdict** — are ground truth.
See [Documentation changes](#documentation-changes) for keeping them consistent.

---

## Prerequisites

You need a **stable Rust** toolchain installed via [`rustup`](https://rustup.rs/).

- **MSRV (`rust-version`): 1.85**, edition 2021.
- The repo **pins its toolchain** in [`rust-toolchain.toml`](rust-toolchain.toml). When
  you run any `cargo` command inside the repo, `rustup` reads that file and
  automatically selects the `stable` channel with the `rustfmt` and `clippy`
  components — the same toolchain CI uses. You do not need to configure anything.

```toml
# rust-toolchain.toml (already in the repo — shown for reference)
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

> [!TIP]
> If `rustup` is already installed, `rustup show` inside the repo confirms it picked up
> the pinned `stable` toolchain plus `rustfmt` and `clippy`. No nightly is required.

---

## Local development

```bash
# 1. Clone
git clone https://github.com/rupeshbharambe24/Gyre.git
cd Gyre

# 2. Build the whole workspace (rustup auto-selects the pinned stable toolchain)
cargo build --workspace

# 3. Test the whole workspace (all 171 tests should pass)
cargo test --workspace

# 4. Run a single crate's tests while iterating (example: the inbound rotor)
cargo test -p gyre-shield

# 4b. Just the property tests for a crate (see "How we test" below)
cargo test -p gyre-fec --test properties

# 5. Run the demos — each prints its mechanism and its HONEST ceiling
cargo run -p gyre-adversary   # THE GATE: correlation sweep + multipath exposure report
cargo run -p gyre-shield      # inbound rotor: MTD ingress hopping + PoW admission
cargo run -p gyre-node        # FAST vs MIX lanes on the same route, timed
cargo run -p gyre-crowd       # k-anon admission governor + staking Sybil-pricing
cargo run -p gyre-obfs        # pluggable transport + entropy meter (appearance only)
cargo run -p gyre-endpoint    # forward-secret ratchet, personas, uniform fingerprint
cargo run -p gyre-directory   # threshold-signed consensus + equivocation detection
cargo run -p gyre-pir         # 2-server IT-PIR (default OFF: full signed download)
cargo run -p gyre-stego       # LSB steganography (situational; trivially detectable)
```

<details>
<summary>Which crates have a runnable demo?</summary>

Nine crates ship a `main.rs` demo binary (the nine `cargo run -p …` lines above). Four
are **lib-only** and have no demo — exercise them through `cargo test`:

- `gyre-common`
- `gyre-sphinx`
- `gyre-fec`
- `gyre-net`

</details>

> [!NOTE]
> The GATE demo (`cargo run -p gyre-adversary`) is the one to read first. It shows,
> with numbers, why mixing is the real correlation-resistance lever, why a tiny crowd
> guts it, and why multipath **widens** partial-observer exposure rather than shrinking
> it. If your change touches the data plane, its story has to survive that report.

---

## Before you open a PR

There are **three gates**. They are **CI-enforced** on every pull request and on
pushes to `main` — if any one of them fails, the PR cannot merge. Run all three
locally first; they are exactly what CI runs, so a green local run means a green
pipeline.

```bash
# Gate 1 — formatting (must already be rustfmt-clean; --check makes no changes)
cargo fmt --all -- --check

# Gate 2 — lint with WARNINGS AS ERRORS (-D warnings). Clippy must be silent.
cargo clippy --workspace --all-targets -- -D warnings

# Gate 3 — the full test suite (all 171 tests)
cargo test --workspace
```

| Gate | Command | What it enforces |
| --- | --- | --- |
| 1. Format | `cargo fmt --all -- --check` | Canonical `rustfmt` style, no diffs |
| 2. Lint | `cargo clippy --workspace --all-targets -- -D warnings` | **Zero warnings** — every warning is a hard error |
| 3. Test | `cargo test --workspace` | Behavior is correct; nothing regressed |

```mermaid
flowchart LR
    A["Branch + code"] --> B["cargo fmt --all -- --check"]
    B --> C["cargo clippy --workspace --all-targets -- -D warnings"]
    C --> D["cargo test --workspace"]
    D --> E["Open PR"]
    E --> F["CI re-runs all three gates"]
    F -->|"all green"| G["Review + merge"]
    F -->|"any red"| A
```

> [!WARNING]
> `-D warnings` means clippy warnings are **errors**. Do not silence a lint with a
> blanket `#[allow(...)]` to get past the gate — fix the code, or, if the lint is
> genuinely wrong for a specific line, add a **narrowly scoped** `#[allow]` with a
> comment explaining why. A green CI run is a claim that the code is clean; keep it
> honest.

Pre-PR checklist:

- [ ] `cargo fmt --all -- --check` is clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is silent
- [ ] `cargo test --workspace` is green (171 tests, or 171 + your new ones)
- [ ] New behavior is covered by a test that asserts **behavior, not timing**
- [ ] A new invariant is covered by a **property**, and a new parser of untrusted input by
      a "never panics on arbitrary bytes" property (see [How we test](#how-we-test-unit-property-fuzz))
- [ ] Any new property was confirmed to **fail** when the code it guards is broken
- [ ] No overclaim introduced (see [Documentation changes](#documentation-changes))

---

## How we test: unit, property, fuzz

Three layers, each catching what the one before it misses. The first two run on stable in
CI; the third is on-demand and needs nightly.

### 1. Unit tests — the named cases

`#[cfg(test)] mod tests` inside each crate. These pin down specific, hand-chosen
behaviours and the exact regressions we care about.

### 2. Property tests — the invariants

`crates/*/tests/properties.rs`, using [proptest](https://proptest-rs.github.io/proptest/).
Each property states an invariant that must hold for *every* input, and proptest generates
hundreds of cases per run and **shrinks any failure to a minimal counterexample**. Two
kinds carry most of the weight:

- **Domain invariants** — "any `data` of the `data + parity` fragments reconstruct the
  message", "a solved puzzle always verifies", "a larger crowd is never treated more
  restrictively", "acceptance tracks the *distinct* signer count".
- **Robustness (fuzz-like) properties** — "parsing arbitrary bytes never panics", applied
  to every parser that reads untrusted input. This gives fuzzing-style coverage on stable,
  inside the normal `cargo test` run.

> [!TIP]
> Properties draw fresh seeds each run, so a single green run is weak evidence. When you
> add or change one, run it several times (`for i in 1 2 3; do cargo test -p <crate>; done`)
> before trusting it — and confirm a new property actually *fails* when you break the code
> it guards. A property that cannot fail is worse than no property.

### 3. Fuzzing — coverage-guided, on demand

`fuzz/fuzz_targets/` holds [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
targets for the same parsers the robustness properties cover; libFuzzer explores deeper
paths than random generation reaches. The `fuzz/` directory is **its own workspace and is
excluded from the root one**, so the stable toolchain CI uses never tries to build it.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cargo +nightly fuzz list                       # sphinx_packet_parse, fec_fragment_parse, …
cargo +nightly fuzz run sphinx_packet_parse     # run until it finds something (Ctrl-C to stop)
cargo +nightly fuzz run stego_extract -- -max_total_time=60
```

Any crash reproducer that fuzzing finds should become a **unit test** (so it is pinned
forever on stable) as part of the fix.

---

## Adding a milestone or crate

Gyre grows by **milestones**, and the unit of a milestone is usually a crate. The
pattern is deliberate — follow it so the workspace stays legible.

### The pattern

1. **One crate per orthogonal concern.** Gyre is a *matrix* of independent
   defenses, not a stack (decision **D10**). A new concern gets its own crate under
   `crates/gyre-<name>` and its own line in the workspace `members` list; it should
   not bolt itself onto an existing crate's responsibilities.
2. **A `lib.rs` with an honest module doc-comment that states the ceiling.** The very
   top of the crate (`//!` doc) says what the mechanism does *and* what it cannot do.
   The limit is a first-class part of the API surface, not an afterthought.
3. **Tests that assert behavior, not timing.** Wall-clock timing is machine-dependent
   and flaky in CI. Assert the *property* — "reassembles from any *m* fragments",
   "rejects an admission below the PoW threshold", "detects an equivocating signer" —
   never "finished in under N milliseconds". Timing belongs in a demo's printout, not
   in a test assertion.
4. **An optional `main.rs` demo that prints the honest ceiling.** If the crate benefits
   from a runnable story, add a demo that prints its mechanism *and* the ceiling in the
   same breath. Lib-only crates (like `gyre-common`, `gyre-sphinx`, `gyre-fec`,
   `gyre-net`) skip this and prove themselves through tests.

### Skeleton for a new crate

```rust
//! # gyre-foo — <one honest line: what this concern is>
//!
//! Mechanism: <what it actually does>.
//!
//! Ceiling (READ THIS): <what it does NOT buy — stated plainly, in-line>.
//! For example: "appearance only; zero anonymity effect", or "detection, not
//! prevention", or "situational — trivially detectable under <condition>".
//!
//! This crate is EXPERIMENTAL and UNAUDITED like the rest of Gyre.

// ... public API ...

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asserts_a_property_not_a_duration() {
        // Assert the behavior/invariant. Never assert wall-clock timing.
    }
}
```

```toml
# crates/gyre-foo/Cargo.toml — inherit workspace-pinned versions
[package]
name = "gyre-foo"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
# Pull audited crates from [workspace.dependencies] — never a fresh primitive (D11).
```

> [!NOTE]
> Adding a crate changes the ground-truth counts. If crate #14 lands with its own
> tests, the "15 crates / 171 tests" numbers move **together, everywhere** — see the
> next section.

---

## Commit & PR conventions

- **Concise, imperative subject line.** "Add entropy meter to gyre-obfs", not "Added…"
  or "This commit adds…". Aim for ~50 characters; put detail in the body.
- **Reference the milestone.** Mention the phase/milestone or the crate the change
  belongs to (e.g. `P3`, `GATE`, `gyre-shield`) in the subject or body so history stays
  navigable.
- **Keep diffs focused.** One concern per PR. Formatting churn, drive-by renames, and an
  unrelated feature do not belong in the same diff — they make review and `git bisect`
  harder. Split them.

| Do | Don't |
| --- | --- |
| `Add PoW admission threshold to gyre-shield` | `updates` |
| `Fix off-by-one in gyre-fec reassembly (any m)` | `fixed a bug and also reformatted everything` |
| `gyre-crowd: gate admission on k-anon set size` | `WIP misc changes` |

**Pull requests** should say what changed, which milestone/crate it touches, and — in
keeping with the ethos — **what you measured**. If the change affects the data plane,
include the relevant demo output (especially the GATE report). A PR that claims a
security or performance improvement without a number is incomplete.

---

## Documentation changes

Docs are held to the same honesty bar as code.

- **Keep the ground-truth numbers consistent across every doc.** The canonical values
  are **14 crates**, **127 tests**, and the **GATE** verdict below. If you change any of
  them, grep the repo and update *all* occurrences in the same PR — a doc that says "12
  crates" or "54 tests" is a bug.
- **Never introduce an overclaim.** Before writing any comparative or absolute claim,
  re-read the anti-overclaim rules in
  [docs/DESIGN.md § "What we can and cannot claim"](docs/DESIGN.md#7-what-we-can-and-cannot-claim).
  A few that catch people:
  - Say "**match / modest win vs modern Tor**", never "beat Tor on speed" unqualified.
  - Never sum inbound-protected clients into the outbound anonymity-set number.
  - **Multipath = probabilistic middle-path hardening, not a reconstruction threshold.**
  - "**Unblockable**" is banned; obfuscation buys "more expensive to block than the
    censor will pay today".
  - Anonymous credentials / staking add **zero** intrinsic Sybil resistance — the scarce
    resource (PoW/stake) does.

### The GATE — the numbers, quoted exactly

> [!WARNING]
> **Optimistic and superseded.** This model uses single-message flows and a greedy
> matcher; both make anonymity look better than it is. `cargo run --release -p gyre-sim`
> re-measures the real code against an optimal attacker and reports **≈ 0.50** where
> this table says `0.11`. Quote [`docs/SIMULATION.md`](docs/SIMULATION.md) for any
> anonymity claim; the table below is a regression signal for the mechanism.

These are the original go/no-go measurements. Reproduce them with `cargo run -p gyre-adversary`.

| flows | window | mix/hop | accuracy | chance | note |
| :---: | :---: | :---: | :---: | :---: | --- |
| 50 | 1000ms | 0ms | 1.00 | 0.02 | baseline: no mixing (FAST lane) |
| 50 | 1000ms | 50ms | 0.11 | 0.02 | MIX lane, healthy crowd |
| 50 | 1000ms | 150ms | 0.04 | 0.02 | more mixing |
| 5 | 1000ms | 150ms | 0.44 | 0.20 | same mixing, tiny crowd → barely helps |

**Multipath exposure** — fraction of flows a partial observer on 20% of paths touches:

| paths | exposure |
| --- | :---: |
| single-path (k=1) | 0.23 |
| multipath (k=3) | 0.56 |

**Verdict:** (1) mixing works and is the real correlation-resistance lever (`1.00 →`
near chance). (2) It is **gated on the crowd** (tiny crowd `0.44` — cleverness never
manufactures anonymity). (3) Multipath does **not** buy partial-observer correlation
resistance — it **widens** exposure (`0.23 → 0.56`); it buys availability and
content-splitting (decision **D7**).

> [!IMPORTANT]
> If a code change moves any of these numbers, the doc numbers move **with it, in the
> same PR**. The measurement is the source of truth; the docs report it.

---

## Code of Conduct

The full policy is in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (Contributor
Covenant v2.1). The short version:

- **Be respectful, be honest, assume good faith.** Technical disagreement is welcome;
  personal attacks, harassment, and bad-faith conduct are not.
- **No overclaiming in discussion either.** This is a security-research project — do not
  present unverified results, exaggerated capabilities, or "unbreakable" framing in
  issues, PRs, or reviews. Bring the measurement.
- **Scope.** These expectations apply in all project spaces: issues, pull requests, code
  review, and commit history.
- **Reporting.** Conduct concerns can be raised via a GitHub **Issue**, or, if the
  matter is sensitive, privately to the maintainer **[@rupeshbharambe24](https://github.com/rupeshbharambe24)**.
  For **security vulnerabilities**, do **not** open a public issue — use GitHub's
  **private vulnerability reporting** (Security Advisories) on the repository instead.

The maintainer may edit, remove, or reject contributions and comments that violate these
expectations.

---

## License

Gyre is licensed under the **MIT License** — see [`LICENSE`](LICENSE).

**By contributing, you agree that your contributions are licensed under MIT** © 2026
rupeshbharambe24. If you are not able to license your contribution under these terms,
please do not submit it.

---

<sub>Maintainer: <a href="https://github.com/rupeshbharambe24">@rupeshbharambe24</a> ·
Repo: <a href="https://github.com/rupeshbharambe24/Gyre">rupeshbharambe24/Gyre</a> ·
Status: experimental, unaudited · See <a href="README.md">README</a> and
<a href="docs/DESIGN.md">docs/DESIGN.md</a>.</sub>
