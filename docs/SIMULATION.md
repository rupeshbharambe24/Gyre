# Gyre — Simulation Results

![status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)
![harness: gyre--sim](https://img.shields.io/badge/harness-gyre--sim-informational.svg)
![attacker: optimal](https://img.shields.io/badge/attacker-optimal%20assignment-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

End-to-end measurements of the fabric under a named adversary, produced by the
[`gyre-sim`](../crates/gyre-sim) harness. Unlike the original GATE, this one drives the
**real protocol code** and attacks it with the **strongest matcher we can construct**.

```bash
cargo run --release -p gyre-sim     # release matters: real crypto is slow in debug
```

> [!WARNING]
> **This supersedes the original GATE numbers for any anonymity claim.** The GATE
> (`gyre-adversary`) reported `0.11` accuracy for the MIX lane at 50 ms/hop. Measured
> properly — multi-packet streams, optimal attacker — the same setting is **≈ 0.50**.
> The old figure was optimistic by roughly **4.5×**. Details in
> [What changed, and why the old numbers were optimistic](#what-changed-and-why-the-old-numbers-were-optimistic).

---

## Contents

- [What is real and what is modelled](#what-is-real-and-what-is-modelled)
- [The attacker](#the-attacker)
- [What changed, and why the old numbers were optimistic](#what-changed-and-why-the-old-numbers-were-optimistic)
- [Results](#results)
- [What these results mean](#what-these-results-mean)
- [Limits of this harness](#limits-of-this-harness)
- [Shadow results — real binaries, simulated network stack](#shadow-results--real-binaries-simulated-network-stack)

---

## What is real and what is modelled

| Real — the actual shipped code | Modelled — simulated |
|---|---|
| Sphinx onion construction and hop-by-hop processing (`gyre-sphinx` over the `sphinx-packet` crate) | Link latency and jitter |
| The per-hop Poisson delay schedule, sampled by the real Loopix sampler and sealed inside each onion | Relay selection, flow start times, packet pacing (seeded) |
| Real X25519 relay keys; every hop peels exactly one real layer | Observer placement |
| Real packet sizes on the wire (fixed-size Sphinx padding) | No queueing, bandwidth limits, or loss |

The delay a relay applies is **extracted from the packet it just decrypted** — not invented
by the harness. The timing under attack is the timing the implementation actually produces.

**Flows are streams, not single messages.** Each flow sends 8 packets over one circuit,
each with its own independent mixing delay. This matters: a single packet carries almost no
timing signal, so modelling one packet per flow makes correlation look far harder than it
is. Real attacks correlate a circuit's whole packet stream, and so does this one.

**Environment.** Apple M5 (10 cores), macOS 26.5.2, rustc 1.96.0, `--release`. 150
concurrent flows × 8 packets, 30 relays, 3 hops, 20 ms links with 10 ms jitter, flows
starting uniformly across a 1 s window. Each figure is the mean of 8 independent runs
(± standard deviation). The real Loopix sampler draws from the OS RNG and is not seedable,
so every result is a distribution, not a fixed number.

## The attacker

Correlation is an **assignment problem**: given a set of entry-side streams and a set of
exit-side streams, decide which belongs to which. The harness gives the attacker:

1. **A maximum-likelihood cost.** The sum of `k` independent exponential hop delays is
   Erlang-distributed, so each candidate pairing is scored by the negative log-likelihood
   of its observed timing gap, summed over the packets in the stream. Pairings where an
   exit precedes its entry are priced as impossible.
2. **An optimal solver.** The Hungarian (Kuhn–Munkres) algorithm finds the globally
   minimum-cost perfect matching in `O(n³)`. No attacker using this cost function can do
   better. (The implementation is verified against brute force for `n ≤ 6`.)

A **greedy** matcher is run on the identical cost matrix, purely to quantify how much a
weak attacker understates the risk.

## What changed, and why the old numbers were optimistic

The original GATE made two choices that both flatter the defence, and its own
documentation had the direction of the error backwards — it claimed the greedy matcher was
chosen "so anonymity never looks better than it is", which is exactly inverted.

| | Original GATE | This harness |
|---|---|---|
| Packets per flow | 1 (single message) | 8 (a stream) |
| Attacker | greedy nearest-match | optimal assignment, maximum-likelihood |
| Code under test | a synthetic timing model | the real Sphinx/Loopix implementation |
| **MIX lane @ 50 ms/hop** | **0.11** | **≈ 0.50** |

Both changes push in the same direction — toward the attacker — which is why they were
worth making. The old harness is still useful as a fast, deterministic regression signal
for the *mechanism*; it is no longer the basis for an anonymity claim.

## Results

### 1 · Mixing vs an optimal attacker

Every relay watched, so coverage is 1.0 and the figure is purely the attacker's ability to
link streams it sees both ends of.

| mix / hop | lane | optimal accuracy | greedy accuracy | chance |
|---:|:---|---:|---:|---:|
| 0 ms | FAST | **1.000** ±0.000 | 0.949 | 0.0067 |
| 10 ms | MIX | **1.000** ±0.000 | 0.989 | 0.0067 |
| 50 ms | MIX | **0.497** ±0.044 | 0.282 | 0.0067 |
| 150 ms | MIX | **0.057** ±0.023 | 0.028 | 0.0067 |
| 500 ms | MIX | **0.021** ±0.013 | 0.016 | 0.0067 |

Three things follow, none of them comfortable:

- **The FAST lane offers no correlation resistance at all.** An observer holding both ends
  links every stream. That is the honest price of Tor-class latency, and it is why FAST
  must never be described as anonymous against an end-to-end observer.
- **10 ms/hop is decorative.** It costs latency and buys essentially nothing.
- **The default 50 ms MIX lane still loses about half the streams.** Meaningful resistance
  needs 150 ms/hop or more — which is well into "messaging, not browsing" latency.

### 2 · The crowd is the binding constraint

Identical 150 ms/hop mixing; only the number of concurrent flows changes.

| flows | optimal accuracy | chance | accuracy vs chance |
|---:|---:|---:|---:|
| 4 | 0.719 ±0.291 | 0.2500 | 2.9× |
| 10 | 0.612 ±0.267 | 0.1000 | 6.1× |
| 25 | 0.320 ±0.089 | 0.0400 | 8.0× |
| 50 | 0.210 ±0.068 | 0.0200 | 10.5× |
| 100 | 0.097 ±0.014 | 0.0100 | 9.7× |
| 150 | 0.063 ±0.019 | 0.0067 | 9.5× |

Accuracy falls as the crowd grows — but so does chance, and the **ratio does not improve**.
Mixing changes how hard each guess is; only a crowd changes how many guesses there are.

### 3 · Partial observer — the end-to-end deanonymisation rate

A flow can only be linked when the observer holds **both** its guard and its exit.
`deanon rate = coverage × accuracy` is the honest headline number. 50 ms/hop mixing.

| relays watched | coverage | linkable flows | optimal accuracy | deanon rate |
|---:|---:|---:|---:|---:|
| 10% | 0.002 | 0.2 | n/a | 0.000 |
| 20% | 0.018 | 2.6 | 1.000 | 0.018 ±0.007 |
| 35% | 0.067 | 10.0 | 0.954 | 0.062 ±0.036 |
| 50% | 0.180 | 27.0 | 0.911 | 0.157 ±0.049 |
| 100% | 1.000 | 150.0 | 0.513 | 0.513 ±0.047 |

> [!IMPORTANT]
> **Low coverage is not safety for the flows inside it.** A 20% observer sees both ends of
> under 2% of flows — but links those it does see with near-certainty, because the
> correlatable set is itself tiny and therefore easy to disambiguate. Coverage protects the
> population; it does nothing for the individual who happens to be inside it.

### 4 · The trilemma, measured

| mix / hop | cover | optimal accuracy | p50 latency | p99 latency | wire overhead |
|---:|---:|---:|---:|---:|---:|
| 0 ms | 0 | 1.000 | 100.0 ms | 112.6 ms | 59.7× |
| 50 ms | 0 | 0.509 | 184.7 ms | 432.1 ms | 59.7× |
| 150 ms | 0 | 0.068 | 352.4 ms | 1102.4 ms | 59.7× |
| 150 ms | 1 | 0.079 | 352.2 ms | 1072.5 ms | 67.1× |
| 150 ms | 3 | 0.072 | 353.9 ms | 1097.1 ms | 82.0× |

The trilemma priced in one table: anonymity costs latency, and cover traffic costs
bandwidth. The **59.7× baseline overhead** is Sphinx's fixed-size padding on a small
payload — real, constant, and the reason this design is not a bulk-transfer network.

Cover traffic deliberately does **not** improve the accuracy column: counting decoys as if
they were real senders is banned by standing anti-overclaim rule 3, so anonymity here is
measured over real concurrent flows only.

### 5 · Realistic heterogeneous traffic

A synchronized crowd where every flow is identical is the *easiest* case to correlate, so
the headline numbers above (uniform traffic) are conservative — attacker-favouring. The
`Traffic::Mixed` model draws each flow from a realistic profile mix (≈55% short
interactive/web bursts, 30% sparse messaging, 15% long bulk transfers). Every flow is still
a modelled **independent sender** — this is measurement realism, not cover dressed up as
senders. 150 flows, all relays watched:

| mix / hop | traffic | optimal accuracy |
|---:|:---|---:|
| 50 ms | uniform | 0.515 ±0.055 |
| 50 ms | **mixed** | **0.335 ±0.063** |
| 150 ms | uniform | 0.078 ±0.024 |
| 150 ms | **mixed** | **0.091 ±0.034** |

Diversity is not a free anonymity win, but it is honest: at 50 ms/hop a realistic mix is
*harder* to correlate than the artificially-synchronized block, because the uniform model
handed the attacker perfectly aligned streams.

### 6 · The crowd curve at real-world scale

The whole thesis is that the crowd must be **large and real**. Published mixnet studies
sweep 10²–10⁵ users; the harness now runs there (parallelised across cores — it was
single-threaded before). A 20%-relay observer watching a heterogeneous crowd:

| flows | coverage | linkable | optimal accuracy | deanon rate |
|---:|---:|---:|---:|---:|
| 150 | 0.028 | 4.2 | 0.750 | 0.0267 ±0.0189 |
| 1 000 | 0.029 | 28.8 | 0.634 | 0.0183 ±0.0071 |
| 3 000 | 0.030 | 88.8 | 0.393 | 0.0108 ±0.0031 |
| 10 000 | 0.028 | 278.2 | 0.230 | 0.0060 ±0.0016 |

As the real, independent population grows 150 → 10 000, the end-to-end deanonymisation rate
falls **0.027 → 0.006**. This is the number the crowd actually moves — and section 4 shows
the counterpart: synthetic *cover* moves it by nothing. Only more **real** senders help.

## What these results mean

- **Mixing works, and it is the only thing that does** — but the useful settings start
  around 150 ms/hop, not the 50 ms default.
- **FAST is a performance lane, not an anonymity lane.** It should be documented that way.
- **The crowd remains the binding constraint**, now measured against a competent attacker
  rather than a convenient one.
- **The honest end-to-end number is the deanonymisation rate**, not raw accuracy, because
  it accounts for how much of the network the adversary actually holds.

## Limits of this harness

Stated plainly, because they bound every number above:

- **It is a simulation.** No real TCP, no cross-traffic, no queueing contention, no packet
  loss, no bandwidth limits. Congestion changes timing, and timing is the whole attack.
- **The network model is simple** — independent per-link latency with uniform jitter. Real
  paths are correlated, bursty, and AS-dependent.
- **The attacker is optimal *for this cost function*.** A model-mismatched attacker (say a
  learned one, as in DeepCorr / DeepCoFFEA) could do better on real traffic shapes.
- **Flow behaviour is synthetic.** Even the `Traffic::Mixed` profiles are plausible
  modelling choices, not distributions fitted to a real capture — the point is *diversity*
  (so the crowd is not an artificially easy synchronized block), not fidelity to any one
  application. Real application traffic would be the next fidelity step.
- **No adaptive adversary.** Nobody drops, delays, or injects packets to create a
  watermark; this measures a *passive* observer only.

## Shadow results — real binaries, simulated network stack

[Shadow](https://shadow.github.io) runs the **real, unmodified** `gyre-relay` / `gyre-client`
/ `gyre-sink` binaries against a simulated network stack, so timing includes real TCP:
connect handshakes, congestion control, and loss. That is what `gyre-sim` models rather than
provides.

It is Linux-only, so it runs in CI ([`.github/workflows/shadow.yml`](../.github/workflows/shadow.yml)),
where GitHub's free runners make it reproducible for anyone at no cost.

**Setup.** Three relays and four concurrent clients across two simulated regions (15 ms
intra-region, 70 ms inter-region with 0.1% loss, 100 Mbit links). Each client sends 10
packets on the MIX lane through `r1 → r2 → r3` to a sink. Shadow v3.3.0.

### What it showed

| Measurement | Result |
|---|---|
| End-to-end delivery | **40/40** payloads |
| End-to-end latency | 3.56 – 4.89 s |
| Client → entry relay, every packet | **140.009 ms**, identical to 5 decimal places |
| **Intra-client reordering (evidence of mixing)** | **4 of 36 adjacent pairs** |
| Raw inversions across all clients | 17 |

```text
c1: [0,1,2,3,4,5,6,7,8,9]  -> in order
c2: [0,2,1,3,4,5,6,7,8,9]  -> REORDERED
c3: [0,2,1,3,4,6,5,7,8,9]  -> REORDERED
c4: [0,1,3,2,4,5,6,7,8,9]  -> REORDERED
```

**Mixing measurably reorders packets over real TCP.** Three of four clients had a packet
overtake one they had sent earlier — which no amount of client drift can explain, because
within a single client the send order is known.

### The reordering rate matches the delay distribution

That identical **140.009 ms** is the interesting number. It is not network jitter; it is the
test client **serializing** — one TCP connect per packet, waiting for each to be accepted
before sending the next. So packets enter the fabric exactly 140 ms apart, and the mixing
has to overcome that gap to reorder anything.

The MIX lane is 50 ms/hop over 3 hops, so a packet's total delay is Erlang(3, 50 ms) — mean
150 ms, σ ≈ 87 ms. Two packets sent 140 ms apart invert when the second one's delay beats
the first's by more than the gap:

| | adjacent-pair inversion rate |
|---|---|
| Predicted, `P(D₂ − D₁ < −140 ms)`, D ~ Erlang(3, 50 ms) | **0.113** → 4.1 of 36 |
| Observed | **0.111** → **4 of 36** |

The implementation produces the delay distribution it claims. A broken or silently-dropped
delay schedule would not have landed here. (With n = 36 the 95% interval is [0.044, 0.253],
so this is a sanity check that would have caught a real bug — not a precision measurement.)

The same model says a client that **didn't** serialize — sending packets back to back
instead of one connect at a time — would invert **~50%** of adjacent pairs at this identical
mixing setting. That is the ceiling by symmetry, not a security claim: two packets injected
at the same instant arrive in either order half the time whether or not anything meaningful
is happening. The point is narrower and worth stating plainly: **the modest reordering here
is a property of the test client, not a weakness of the mixing.**

### The caution that matters

> [!IMPORTANT]
> **The naive metric overstates mixing by ~4×.** The raw count of out-of-order arrivals is
> 17; only **4** are real. The other 13 are independent clients drifting apart, which
> happens with no mixing at all. Any measurement that does not attribute payloads to a
> sender cannot tell these apart — an earlier version of this experiment could not, and 17
> is the number it would have reported.

### What this does and does not say

> [!WARNING]
> **Reordering is not anonymity, and this section must not be read as corroborating the
> attacker numbers above.** Shadow shows the mixing *mechanism* behaves as specified over a
> real network stack. It says nothing about whether an adversary can correlate flows — there
> is no adversary in this experiment. The anonymity figures come from `gyre-sim`, and they
> are the ones that say 50 ms/hop leaves an optimal attacker at ≈0.50. The two harnesses
> answer different questions; agreement on one is not evidence about the other.

### What Shadow added that `gyre-sim` could not

`gyre-sim` models the network, so it never charged 140 ms for a TCP connect — and it is that
one number, not the mixing setting, that governs how much reordering was visible here. The
local loopback testnet (`./scripts/testnet.sh`) reorders far more freely because its sends
are ~1 ms apart. Same code, same mixing parameter, three different pictures depending on how
honestly the network and the client are modelled. That is the argument for running all
three.

### Limits of this run

- **Small.** Three relays, four clients, 40 packets. Enough to show the mechanism operates
  over real TCP; nowhere near enough to say anything about behaviour at scale.
- **Synthetic, serialized traffic.** Fixed-size sends, one connect at a time — not how a
  real application behaves, and as shown above that choice dominates the reordering result.
- **A toy topology.** Two regions and one slow link, not a model of the internet.
- **No adversary.** See the warning above.

Reproduce: trigger **Shadow simulation** from the Actions tab, or run locally on Linux per
[`sim/shadow/README.md`](../sim/shadow/README.md).

---

<sub>Reproduce with `cargo run --release -p gyre-sim`. Harness source:
[`crates/gyre-sim`](../crates/gyre-sim). Primitive microbenchmarks are separate — see
[`BENCHMARKS.md`](../BENCHMARKS.md).</sub>
