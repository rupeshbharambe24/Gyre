# Whirlpool — Design

A condensed, public design summary. It states what the system is, the adversary
it targets, the mechanisms it uses, and — just as importantly — the limits it
does not cross.

## 1. Two rotors, one fabric

The two goals point in opposite directions and need different rules, so they are
two rotors sharing one relay fabric (Tor already proves this is possible: client
anonymity plus onion-service origin-hiding).

- **Outbound — protect a person.** Traffic leaves you toward services you don't
  own, watched by a powerful observer. Goal: unlinkability of *you ↔ destination*.
- **Inbound — protect a system.** Traffic arrives toward an asset you own. Goal:
  hide the origin, gate access, shrink the attack surface.

## 2. Threat model (named up front)

Everything is measured against these. We do **not** claim to beat a global
passive observer at low latency — nobody can.

| Adversary | In scope? |
|---|---|
| Partial network observer (sees some links, correlates by timing) | **Primary target** |
| Censoring ISP / organisation | Yes (obfuscation) |
| Sybil relay operators | Yes (staking / PoW / reputation) |
| Global passive observer | **Out of scope at low latency** (stated openly) |
| Endpoint attacker (has your device) | Mitigated, never fully solved |

## 3. The physics ceiling

1. **Anonymity trilemma** — strong anonymity, low latency, low overhead: pick ~two.
2. **Global observer** — beats any low-latency design by end-to-end correlation.
3. **Endpoint & crowd** — a login or fingerprint deanonymises you regardless of the
   network, and anonymity is bounded by the number of *concurrent* users.

## 4. Outbound rotor — mechanisms

- **Onion routing** (Sphinx, 3 hops): no relay learns both ends. Capped at 3 on
  purpose — more hops buy negligible anonymity for real latency.
- **Mixing** (per-hop Poisson delay) + **cover traffic** (Loopix loops): breaks
  timing correlation, at an honest latency cost.
- **Erasure-coded multipath** (Reed–Solomon `m`-of-`k` across disjoint paths):
  *probabilistic middle-path hardening* against a partial observer. **Not** a
  reconstruction-threshold guarantee — endpoints remain correlation points.
- **Adaptive FAST/MIX lanes**: the flow class is sealed inside the onion. FAST is
  onion-only (Tor-class latency); MIX pays latency for stronger resistance. This
  is an honest menu of trilemma points, not a way around it.

## 5. Inbound rotor — mechanisms

- **Rendezvous**: the origin publishes no routable address; clients meet it at a
  relay that only ever sees ciphertext, and TLS/Noise terminates *only at the
  origin* — no intermediary holds plaintext.
- **Moving-target-defense** address hopping via `HMAC(key, time_window)`: the
  reachable surface moves; authorised clients follow it, scanners can't. (Serves a
  closed/authorised client set — not arbitrary open-web clients.)
- **Proof-of-work admission** that scales with load: prices out floods.
- **Unlinkable capability tokens**: fast-path trusted clients without identity.

Honest limit: this hides the origin and prices admission, but offers **no L3/L4
volumetric defence** and depends on a healthy relay crowd.

## 6. Orthogonal hardening (added by threat, not by default)

Each covers a distinct dimension an adversary can observe; add one only when your
adversary attacks that dimension.

1. **Obfuscation / pluggable transport** — make the first hop look like nothing or
   ordinary HTTPS. "Unblockable" is impossible; this raises the censor's cost.
2. **Endpoint isolation + data minimisation** — compartmentalised identities,
   ephemeral keys, one uniform client fingerprint (which feeds the crowd).
3. **Anonymous credentials** — prove "authorised" with zero identity. These add
   *zero* intrinsic Sybil resistance; the scarce resource (PoW/stake) does.
4. **Decentralisation + attestation** — threshold-signed directory + reproducible
   builds; moves trust to many parties whose cheating is publicly detectable.
5. **Deniability / steganography** — situational: hide *that* you use it at all.
6. **PIR for rendezvous lookups** — hide *which* service you seek (default off for
   the relay list; downloading it in full is cheaper and leak-free at this scale).

## 7. What we can and cannot claim

- vs **VPN**: stronger on trust/anonymity (no single operator sees both ends);
  slower — a VPN wins on latency and simplicity.
- vs **Tor**: an honest mixing dial and modern transport let us *compete* on
  latency; Tor's decisive advantage is its crowd. We do not surpass it.
- vs **Nym**: we add an inbound rotor it doesn't have; on outbound mixnet
  anonymity Nym wins on a live crowd, incentives, and audits.
- vs **Cloudflare** (inbound): a trust-topology win for authenticated tunnels; we
  cannot match anycast scrubbing capacity.

The binding constraint everywhere is the same — **crowd**. Cleverness never
manufactures anonymity or beats a global observer, and this project is careful to
keep saying so.

## 8. Build order (measurement-gated)

`P0 core (Sphinx → mixing → multipath → lanes)` → **gate: measure correlation vs
latency against a baseline** → `P2 transport + inbound wedge` → `P3 the six
hardening additions` → `P4 scale + crowd`. Ship nothing to real users until the
core is measured, the crypto is externally audited, and a real crowd-bootstrap
plan exists.

## 9. Tech stack (never roll your own)

Rust; **Sphinx** (`sphinx-packet`) + **Noise**/**WireGuard** + **QUIC/MASQUE**;
**reed-solomon-erasure**; Loopix-style mixing; `x25519-dalek` / `libsodium`.
Hardening uses obfs4/uTLS/Snowflake, libsignal, Privacy-Pass/RLN, threshold-BLS +
reproducible builds, and PIR only where it earns its cost. Testing uses Shadow,
container/netns devnets, and a custom adversary-emulation harness.
