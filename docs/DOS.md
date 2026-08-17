# Gyre — DoS / DDoS defense plan

![status: partial](https://img.shields.io/badge/status-partial%20%C2%B7%20demo--only-orange.svg)
![layer: L7 admission](https://img.shields.io/badge/layer-L7%20admission-informational.svg)
![volumetric: out of scope](https://img.shields.io/badge/volumetric%20L3%2FL4-out%20of%20scope%20(D22)-red.svg)

This document says, layer by layer, exactly what Gyre does and does not do against denial of
service — grounded in the code, with every mechanism tagged, and the one boundary that must
never be blurred stated first.

> [!CAUTION]
> **Gyre does not, and cannot, defend against a volumetric L3/L4 flood.** A UDP/ICMP/SYN or
> amplification flood (memcached amplifies ~51,000×) saturates the link, NIC, or kernel
> packet path **before any Gyre code runs** — the CPU spent dropping junk *is* the denial of
> service. Absorbing that is capacity: anycast scrubbing measured in Tbps and PoPs. Gyre
> neither has it nor claims it (decision **D22**). Anything that says otherwise is wrong.
>
> **What Gyre is** is the onion-service model: it **removes the origin as a target** and
> **prices application-layer admission**. It sits *behind* a scrubber and makes that scrubber
> un-bypassable; it never *replaces* one. Read the whole of §1 before pitching this to anyone.

---

## Contents

- [The one-paragraph answer](#the-one-paragraph-answer)
- [1 · L3/L4 volumetric — the hard boundary](#1--l3l4-volumetric--the-hard-boundary)
- [2 · L4 state-exhaustion — SYN flood & slowloris](#2--l4-state-exhaustion--syn-flood--slowloris)
- [3 · L7 application floods — Gyre's strongest layer](#3--l7-application-floods--gyres-strongest-layer)
- [4 · Origin-hiding & target removal](#4--origin-hiding--target-removal)
- [5 · Sybil / registration floods](#5--sybil--registration-floods)
- [6 · Internal amplification & fairness](#6--internal-amplification--fairness)
- [Status legend](#status-legend)
- [Prioritized build roadmap](#prioritized-build-roadmap)
- [How it compares](#how-it-compares)

---

## The one-paragraph answer

> Gyre is an onion-service-style overlay. It removes the origin as a target — the protected
> server dials out and publishes no inbound address, so the most common kill, resolving and
> flooding the origin IP, has nothing to aim at — and it prices application-layer admission
> with a stateless, single-use, load-scaled proof-of-work that the attacker pays and the
> server verifies in one hash. That genuinely defeats L7 connection floods, slowloris on the
> guarded handshake, issue-endpoint and reflection abuse, and replay. What it does **not** do,
> and cannot by physics, is absorb a volumetric L3/L4 flood — that lives behind an anycast
> scrubber and kernel SYN cookies, which are a **prerequisite**, not an add-on. And, said
> plainly: today all of these L7 defenses are reachable only through the `gyre-shield` demo
> binary — the shipped `gyre-relay` is still ungated — so productionizing a guarded daemon is
> the top remaining item. Gyre **complements** a scrubber and makes it un-bypassable; it never
> replaces one.

> [!IMPORTANT]
> **The maturity caveat is load-bearing.** Every "BUILT" defense below is real, wired, and
> tested — but only inside `gyre-shield`'s demo/test harness. The deployed `gyre-relay` runs
> the *ungated* Sphinx `RelayServer`. "Built and tested" is not "deployed." Productionizing
> the guarded relay ([roadmap #1](#prioritized-build-roadmap)) is what turns this plan from
> true-in-principle into true-in-the-field.

---

## 1 · L3/L4 volumetric — the hard boundary

**Verdict: `gyre-cannot` — physics (D22).** Attacks: UDP/ICMP flood, SYN flood (bandwidth
variant), reflection/amplification (DNS, NTP, SSDP, CLDAP, memcached).

Gyre's *only* contribution at this layer is topological, not capacity: **origin removal**
(`crates/gyre-shield/src/rendezvous.rs`, BUILT). Because the origin binds no listener and only
dials out, there is no origin IP anywhere in DNS, certs, or routing to flood — which
eliminates the origin-IP-leak / CDN-bypass attack class and makes a front scrubber
**un-bypassable**. That is a *targeting* win. It adds **zero bits of absorption**: the flood
simply lands on the relay instead, which is a real socket on a real link.

**Required pairing (a prerequisite, not an add-on):**

| Layer | Mechanism | Owner |
|---|---|---|
| Transit edge | Anycast scrubbing / DDoS-protected transit (Cloudflare Magic Transit, Akamai Prolexic, AWS Shield Advanced class) | provider |
| Transit edge | Upstream ACLs (block unused reflection vectors), BGP RTBH, Flowspec | transit/ISP |
| Relay host | Kernel SYN cookies — `net.ipv4.tcp_syncookies=1` | one sysctl |
| Source networks | BCP38 source-address validation (out of everyone's hands here) | third parties |

> Gyre's own stateless challenge issue is the **L7 analogue** of a SYN cookie — but it is
> **not a substitute** for the kernel one, because Gyre's code runs one layer above the
> half-open queue.

---

## 2 · L4 state-exhaustion — SYN flood & slowloris

**Verdict: `partial`.** The classic half-open SYN flood is the kernel's job (SYN cookies,
above). The **slowloris** variant — a completed TCP connection that then stalls Gyre's
application-level admission handshake — is squarely Gyre's, and is defended today on the
guarded path.

| Mechanism | Status | Evidence |
|---|---|---|
| Admission handshake timeout (slowloris deadline) | **BUILT** | `RelayConfig.handshake_timeout`; whole `admit()` future wrapped in `tokio::time::timeout`; test `a_guarded_relay_drops_a_slowloris_that_never_finishes_the_handshake` |
| In-flight handshake **count** cap (Semaphore) | **BUILT** | `RelayConfig.max_inflight`; permit taken before spawn, dropped after handshake; test `a_guarded_relay_bounds_concurrent_handshakes` |
| Global cap on **parked** connections | **BUILT** | `RelayConfig.capacity`; `Error::AtCapacity`; test `a_guarded_relay_never_parks_beyond_capacity` |
| Cookie length cap (memory-amplification guard) | **BUILT** | `RelayConfig.max_cookie_len`; test `a_guarded_relay_refuses_an_oversized_cookie` |
| Stateless self-authenticating challenge (SYN-cookie analogue) | **BUILT** | `admission.rs` `issue()` stores nothing; test `issuing_stores_nothing` (10k issues → 0 stored) |
| Spent set bounded by TTL, not traffic | **BUILT** | `admission.rs` prunes on `redeem`; test `the_spent_set_is_bounded_by_ttl_not_by_traffic` |
| Per-frame allocation bound (`MAX_FRAME` = 1 MiB) | **BUILT** | `gyre-net` `read_frame` rejects before allocating |
| Parked-stream **TTL reaper** (evict idle parks by age) | **NEEDED** | capacity caps count, not hold-time; a patient squatter holds every slot |
| Splice idle/duration timeout | **NEEDED** | `copy_bidirectional` has no idle cap; lower priority (pair already paid PoW) |
| Kernel SYN cookies (half-open flood) | **NEVER** (host) | below `accept()`; OS config |
| Volumetric SYN / link saturation | **NEVER** (D22) | scrubber territory |

> This session closed three of the gaps the design pass flagged: the slowloris **duration**
> bound, the in-flight **count** bound, and the cookie length cap. What remains here is the
> parked-TTL reaper and the (lower-priority) splice idle timeout.

---

## 3 · L7 application floods — Gyre's strongest layer

**Verdict: `gyre-can-help`.** This is where origin-removal and admission-pricing are genuinely
built, wired, and demonstrated (`cargo run -p gyre-shield` refuses a live 50-connection flood
while admitting a client that solves the puzzle).

**Built:** load-scaled PoW admission (server verifies in one HMAC + one hash while the
attacker pays ~2^bits work); the stateless issue (SYN-cookie) property; anti-replay
single-use; authenticated difficulty (a client cannot downgrade a flood-level puzzle); and the
connection-exhaustion bounds from §2.

**The honest weakness — SHA-256 is not memory-hard.** A GPU/ASIC out-computes an honest mobile
CPU, so under flood the attacker clears the 20-bit puzzle cheaply while real clients suffer —
the asymmetry runs *backwards* against your own users. The fix mirrors **Tor proposal 327**:
migrate the puzzle to a memory-hard function with cheap asymmetric verify (**Equi-X**), and
switch difficulty from exponential leading-zero-bits to Tor's linear effort encoding.

> **Effort, corrected during review:** this is *not* a hash swap, but it is cheaper than first
> feared — Tor's Arti project now ships pure-Rust [`equix`](https://crates.io/crates/equix) and
> [`hashx`](https://crates.io/crates/hashx) crates, so the pure-Rust posture (**D11**) is
> preserved. The work is: define a `trait Puzzle`, provide an `equix` impl behind a feature
> flag, switch to linear-effort encoding, and bench that the botnet-GPU : laptop-CPU cost ratio
> stays near 1:1. Days to ~1 week. The surviving caveat: `equix`/`hashx` are **LGPL-3.0**, so a
> licensing sign-off is real. Even memory-hard PoW only denies *hardware* amplification — it
> does not stop a large enough botnet of ordinary CPUs, and nothing at L7 touches L3/L4.

**Also needed:** per-source/per-identity rate limiting (Tor prop-305 analogue, keyed on the
capability token not raw IP), and a rate-aware AIMD/EWMA effort controller (today the load
signal is instantaneous parking occupancy, so a flood that never successfully parks does not
raise difficulty).

**A genuine boundary, not a bug:** the relay splices **opaque bytes** and never parses
requests, so expensive-query abuse *inside* an admitted session is the origin's job (per-request
PoW, quotas, a WAF), not the relay's. Gyre prices *admission*, the same scope as Tor prop-327.

---

## 4 · Origin-hiding & target removal

**Verdict: `gyre-can-help`** — the real structural win a CDN cannot match.

- **BUILT — origin dial-out:** the origin publishes no inbound address, so the single most
  common kill (resolve the origin IP, flood it directly) has no target. A reverse-proxy CDN's
  origin IP routinely leaks (historical DNS, cert SANs, direct-route misconfig) and is flooded
  *around* the scrubber — that is how most "protected" sites actually die. A dial-out origin
  has no back-door address to leak.
- **BUILT — fungible relay:** the relay is a pure opaque byte-pump holding no location secret,
  so flooding one leaks nothing and costs the attacker only a commodity meeting point.
- **BUILT (closed set) — MTD ingress hopping:** the ingress is `HMAC(key, window)`, so even the
  relay address can't be pre-aimed by a party without the key.
- **NEEDED — multi-relay pool + client failover:** park the origin on *k* relays under distinct
  per-relay cookies; the client fails over to a survivor. Flooding one drops it from the pool;
  denying the service requires flooding all *k*, dividing the attacker's per-target volume by
  *k*. Directory primitives exist (`gyre-directory` signed `RelayDescriptor`s); the origin
  supervisor and client failover dialer do not (~1–2 weeks, no new crypto).
- **NEEDED — authenticated cookies:** today the cookie is an unauthenticated bearer secret, so
  a party that learns it can race the client for the parked peer. Fix with an end-to-end
  handshake that keeps the relay oblivious.

> **Quantified honestly:** origin-hiding takes the cost to hit the *origin* from ~free to
> *impossible — no address exists*, and takes the cost to deny the *service* from flooding one
> known IP to flooding every relay in a *k*-sized, per-window-hopping pool, each still needing
> its own scrubber. A bounded constant-factor targeting win **plus** an absolute origin-survival
> guarantee — a complement to a scrubber, never a replacement.

---

## 5 · Sybil / registration floods

**Verdict: `partial`.** Pricing an identity with a scarce resource (PoW / stake) and the
anonymous capability token both exist and are tested — but two honest points:

- Credentials **authorize**; they do not make identities **scarce**. Only a scarce resource
  does. PoW gives *relative* pricing, not *absolute* scarcity — a big enough botnet still pays.
- **Finding F14 — issuance is currently a free oracle.** `Issuer::issue` takes a blinded point
  and *no proof of payment*, so as wired the token is a **free, unlimited skip-the-PoW
  credential** — a Sybil *bypass*, not a defense. **The token→skip-PoW branch must not be wired
  into `admit()` until F14 is fixed** (bind issuance to a spent admission: 1 puzzle → ≤1 token →
  ≤1 admission; ~1 day, no new crypto).

---

## 6 · Internal amplification & fairness

**Verdict: the amplification/reflection surface is genuinely closed; fairness is not.**

- **Closed:** the asymmetry points at the attacker (client pays ~2^bits, server verifies in one
  hash); the issue endpoint is stateless over TCP so it cannot be a reflector; per-frame
  allocation is capped before allocation (`MAX_FRAME`); the spent set is TTL-bounded.
- **Open — no per-source fairness.** The peer address is discarded at `accept()`, so one solver
  can monopolize every slot. This is the per-source rate limiter from §3, and it is the main
  fairness gap.

---

## Status legend

| Tag | Meaning |
|---|---|
| **BUILT** | Implemented, tested, and exercised end-to-end (in the `gyre-shield` demo/test harness) |
| **PARTIAL** | Library exists or works for a closed set, but not fully wired / not deployed |
| **NEEDED** | Design only — not in the code; effort estimated below |
| **NEVER** | Out of scope by physics or by layer (kernel/scrubber territory), D22 |

---

## Prioritized build roadmap

Ordered by what actually unblocks real-world defense, with rough effort. Items marked ✅ were
completed this session.

| # | Item | Effort | Why it matters |
|---|---|---|---|
| 0 | Contract anycast scrubbing + `net.ipv4.tcp_syncookies=1` | ops, ~0 code | The only volumetric answer. A prerequisite; Gyre's origin-hiding makes it un-bypassable |
| 1 | **Productionize the guarded relay as the deployable daemon** | small–moderate | Every BUILT defense is demo-only until this ships; the shipped relay is ungated |
| ✅ | In-flight handshake cap (Semaphore) | done | Bounds the *count* of concurrent handshakes, not just each one's duration |
| ✅ | Slowloris handshake timeout | done | Bounds each handshake's *duration* |
| ✅ | Cookie length cap | done | Removes the `capacity × 1 MiB` parked-map amplification |
| 2 | Parked-TTL reaper | moderate | A patient squatter holds every parked slot forever without it |
| 3 | Per-source / per-identity rate limiting (keyed on the token, not IP) | moderate | Zero fairness today; one source monopolizes all slots |
| 4 | Fix **F14** — bind token issuance to a spent admission | ~1 day | Must land *before* the token skip-PoW branch is wired, or it ships a free bypass |
| 5 | Splice idle/duration timeout | minor | Admitted pairs hold a task + two sockets indefinitely |
| 6 | Rate-aware AIMD/EWMA difficulty controller (prop-327) | moderate | Occupancy-only load signal misses a flood that never parks |
| 7 | Memory-hard PoW via pure-Rust `equix`/`hashx` + linear effort | ~days–1 wk + LGPL sign-off | SHA-256 lets a GPU beat honest mobile clients — the asymmetry runs backwards |
| 8 | Multi-relay pool + authenticated cookies | ~1–2 wks each | Dilutes a relay flood ~linearly by *k*; closes the bearer-cookie splice race |

---

## How it compares

**vs. Cloudflare (Magic Transit / Shield-class).** Gyre loses, unambiguously, on volumetric
absorption (multi-Tbps of scrubbing vs Gyre's zero bits and never), on L7 rate intelligence,
managed rules, bot scoring, and per-request WAF — and it can't even *see* expensive-query abuse
inside an admitted session (it splices opaque bytes). Where Gyre does **not** lose: the
origin-IP-leak / CDN-bypass class. A CDN origin IP routinely leaks and gets flooded around the
scrubber; a dial-out origin has no inbound address to leak. So the honest pitch is not "instead
of Cloudflare" — it is "**Gyre behind Cloudflare makes the scrubber un-bypassable** in a way a
CDN origin can't be." Complement, not replacement.

**vs. Tor onion services.** This is the fair comparison — Gyre is a re-implementation of the
same model (rendezvous, no origin address, PoW admission = prop-327, per-source edge limiting =
prop-305). Gyre currently **loses to Tor** on two things: Tor ships **Equi-X memory-hard PoW in
production** (Gyre is on SHA-256, so the asymmetry runs backwards), and Tor has a *deployed*
gated service (Gyre's gate is demo-only). Gyre is **at parity or better** on the
stateless-issue / SYN-cookie property, the TTL-bounded spent set, and the VOPRF capability-token
construction — clean and tested, *once F14 is fixed*. Bluntly: Gyre is prop-327 / onion-services
minus the memory-hard puzzle minus deployment — both now cheap-to-close items (#1 and #7).

---

<sub>Every code claim here is grounded in `crates/gyre-shield` and `crates/gyre-net`; run
`cargo test -p gyre-shield` and `cargo run -p gyre-shield` to reproduce. External figures:
[memcached amplification](https://www.cloudflare.com/learning/ddos/memcached-ddos-attack/),
[Tor onion-service PoW / Equi-X](https://spec.torproject.org/hspow-spec/),
[`equix`](https://crates.io/crates/equix).</sub>
