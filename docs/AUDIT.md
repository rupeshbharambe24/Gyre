# Gyre — Cryptographic Audit Package

![status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)
![audit: not started](https://img.shields.io/badge/external%20audit-not%20started-red.svg)
![scope: capability token](https://img.shields.io/badge/scope-capability%20token-informational.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

Everything an external reviewer needs to assess Gyre's **one hand-built cryptographic
construction**: the anonymous capability token in
[`crates/gyre-shield/src/token.rs`](../crates/gyre-shield/src/token.rs).

> [!CAUTION]
> **No external audit has taken place.** This document is the *package* prepared for one,
> including a self-review that already found and fixed a critical flaw. A self-review is
> not an audit — it is the author checking their own work, which is exactly the thing an
> audit exists to distrust.

---

## Contents

- [1. Scope](#1-scope)
- [2. Specification](#2-specification)
- [3. Security model](#3-security-model)
- [4. Deviations from RFC 9497](#4-deviations-from-rfc-9497)
- [5. Self-review findings](#5-self-review-findings)
- [6. Open questions for the auditor](#6-open-questions-for-the-auditor)
- [7. Test vectors](#7-test-vectors)
- [8. What is out of scope](#8-what-is-out-of-scope)

---

## 1. Scope

**In scope — the only hand-rolled cryptography in the project:**

| Component | File | ~Lines |
|---|---|---|
| Blind VOPRF capability token (blind / issue / DLEQ prove + verify / unblind / redeem) | `crates/gyre-shield/src/token.rs` | ~330 |

**Explicitly not in scope** — these are audited upstream crates used as-is, per design
decision **D11** (*never roll your own crypto*):

`sphinx-packet` (onion format) · `curve25519-dalek` (ristretto255, scalars) ·
`x25519-dalek` · `ed25519-dalek` · `sha2` · `hmac` · `reed-solomon-erasure` · `zeroize`

Gyre's own code composes these; it does not reimplement them. The token is the one place
where a *protocol* was assembled by hand, which is why it is the audit target.

## 2. Specification

Group: **ristretto255** (prime order `ℓ`, no cofactor, no small-order points).
Hash: **SHA-512**. `G` is the ristretto255 basepoint.

### 2.1 Primitives

```text
H(seed)          = ristretto255_from_uniform_bytes(
                       SHA-512( "gyre-capability-token-v1/hash-to-group" ‖ seed ) )
                   where seed is exactly 32 bytes (fixed by type, so ‖ is unambiguous)

issuer key       k  ←$ Z_ℓ            (or k = SHA-512("…/issuer-key" ‖ seed32) mod ℓ)
public key       Y  = k·G             (published via the signed directory consensus)
```

### 2.2 DLEQ proof (Chaum–Pedersen, Fiat–Shamir)

Proves `log_G(Y) == log_B(Z)` — that the issuer evaluated with the key behind its
*published* public key.

```text
Prove(k, Y, B, Z):
    r  ←$ Z_ℓ
    A₁ = r·G ,  A₂ = r·B
    c  = SHA-512( "gyre-capability-token-v1/dleq" ‖ G ‖ Y ‖ B ‖ Z ‖ A₁ ‖ A₂ ) mod ℓ
    s  = r + c·k
    return (c, s)

Verify(Y, B, Z, (c, s)):
    A₁' = s·G − c·Y
    A₂' = s·B − c·Z
    accept iff  SHA-512( "…/dleq" ‖ G ‖ Y ‖ B ‖ Z ‖ A₁' ‖ A₂' ) mod ℓ  ==  c
```

All six transcript elements are compressed ristretto points of exactly 32 bytes, so the
concatenation is unambiguous without length prefixes.

### 2.3 Protocol

```text
Client                                   Issuer (secret k, published Y = k·G)
------                                   ------------------------------------
seed ←$ {0,1}^256
r    ←$ Z_ℓ
T = H(seed)
B = r·T                    ──── B ───▶
                                         Z = k·B
                                         π = Prove(k, Y, B, Z)
                           ◀── Z, π ────
assert Verify(Y, B, Z, π)      ← REQUIRED. Y must come from the signed consensus,
                                 never from this response.
N = r⁻¹·Z  ( = k·T )
token = (seed, N)

--- later, unlinkably ---
                           ── seed,N ─▶  accept iff N == k·H(seed)
                                         and seed ∉ spent;  then spent ∪= {seed}
```

Epochs: `Issuer::rotate()` draws a fresh `k`, republishes `Y`, and clears `spent`.

## 3. Security model

**Adversary.** A malicious *issuer* (which is also the verifier), and separately a network
adversary that observes issuance and redemption traffic. The issuer is assumed able to
choose its keys freely and to log everything it sees.

**Properties claimed:**

| # | Property | Informal statement |
|---|---|---|
| P1 | **Unlinkability** | The issuer cannot associate a redemption with the issuance that produced it, better than guessing among concurrently issued tokens. |
| P2 | **One-more unforgeability** | A client that completed `n` issuances cannot produce `n+1` tokens that verify. |
| P3 | **Single use** | A token that has been redeemed cannot be redeemed again within an epoch. |
| P4 | **Key consistency** | A client detects an issuer that evaluates with any key other than its published one. |

P1 depends on P4 — that dependency is the flaw found in the self-review below. P2 rests on
the one-more-DH assumption in ristretto255 (as in RFC 9497 and Privacy Pass); **no proof is
offered here**, and confirming that this specific composition inherits it is a core task
for the auditor.

**Anonymity-set caveat.** P1 is unlinkability *within the set of tokens issued in the same
epoch and redeemed in the same window*. If one client is the only redeemer in a window, the
timing links it regardless of the cryptography. That is the crowd constraint that governs
the whole project, not a property the token can fix.

## 4. Deviations from RFC 9497

The construction follows RFC 9497's *shape*, not its letter. Deviations matter because they
break interoperability **and** mean the RFC's security analysis is not inherited.

| Area | RFC 9497 (ristretto255-SHA512) | This implementation | Assessment |
|---|---|---|---|
| Hash-to-group | `expand_message_xmd` with DST `HashToGroup-OPRFV1-\x00-…` | bare SHA-512 → `from_uniform_bytes` | Believed sound as a random oracle to the group (this *is* the ristretto one-way map on 64 uniform bytes), but **not RFC-interoperable** and not covered by the RFC's proofs. |
| DST format | RFC-specified versioned DSTs | custom `gyre-capability-token-v1/*` strings | Distinct per use, so no cross-protocol collision within Gyre; not RFC-compatible. |
| Mode | OPRF / VOPRF / POPRF | VOPRF only | Intentional. |
| Proof | DLEQ over the RFC's transcript encoding | Chaum–Pedersen over a custom transcript | Standard construction, non-standard encoding. |
| Batching | Batched evaluation + one proof | none (one proof per issuance) | Performance only; costs ~25 µs/issuance (see [BENCHMARKS.md](../BENCHMARKS.md)). |
| Key commitment / rotation schedule | out of scope for the RFC | `rotate()`, operator-driven | Policy left to the deployment; see finding F3. |

**Consequence, stated plainly:** this is *not* an RFC 9497 implementation and must not be
described as one. It is an independent construction that borrows the RFC's design.

## 5. Self-review findings

Found by reviewing this code against RFC 9497 while preparing this document. **F1 was
critical and is fixed; the reproduction is retained as a regression test.**

### F1 — CRITICAL (fixed): no DLEQ proof ⇒ unlinkability fully broken

The construction was documented as a "blind **V**OPRF" but carried **no proof** — it was
the base OPRF mode. That allows textbook **key partitioning**:

1. The malicious issuer uses a distinct key `kᵢ` per client, publishing whatever it likes.
2. The client had no way to check which key was used, so it accepted.
3. At redemption the issuer tries every key; exactly one verifies, identifying the issuance
   session and therefore the client.

A proof-of-concept against the unprotected code **linked 5 of 5 redemptions**. P1 was not
merely unproven — it was absent.

**Fix:** implemented the DLEQ proof (§2.2); `unblind` now refuses a token whose proof does
not verify against a **caller-supplied, out-of-band** public key. The same scenario now
links **0 of 5** — see
[`tests/token_unlinkability.rs`](../crates/gyre-shield/tests/token_unlinkability.rs).

> [!IMPORTANT]
> The fix is only effective if `Y` is pinned from the **threshold-signed directory
> consensus** (`gyre-directory`). Verifying a proof against a key the issuer supplied in the
> same response proves nothing — the attacker simply sends the matching key.
> **This wiring is now implemented** (see §5a): the consensus body is a typed
> `NetworkParams` document carrying the issuer key, and `PublicKey::from_verified_params`
> takes a `VerifiedParams` that can *only* be produced by threshold verification. The
> unverified path still exists for tests but is named `from_unverified_bytes`, so a grep
> finds every place trust was assumed.

### F1a — key distribution, now implemented (was open question Q4)

The DLEQ proof is only as good as the provenance of the key it is checked against, so the
consensus now carries that key in a typed, canonically encoded body:

- `gyre-directory::NetworkParams` — magic ‖ version ‖ epoch ‖ **issuer public key** ‖ PoW
  difficulty ‖ MTD window ‖ relay list. **Strict** decoding: exact length, known magic and
  version, and **no trailing bytes**, so each document has exactly one valid encoding. A
  lenient parser here would let a signature over one byte string appear to cover another.
- `gyre-directory::VerifiedParams` — constructible *only* by `verify_consensus`, which
  requires a non-zero threshold, enough distinct valid signatures, a well-formed body, and
  that the body's epoch matches the envelope (so a signed body cannot be spliced into a
  different epoch).
- `gyre-shield::token::PublicKey` — inner bytes private; the blessed constructor takes
  `&VerifiedParams`.

End-to-end coverage is in
[`tests/consensus_pinned_key.rs`](../crates/gyre-shield/tests/consensus_pinned_key.rs),
including the full attack: a rogue issuer answering with a valid proof *for its own key* is
refused because the client pinned the consensus key.

### F8 — HIGH (fixed): `accept_consensus` accepted unsigned documents at threshold 0

Found while wiring the above. `accept_consensus(..., threshold: 0)` evaluated
`distinct_valid_signers(...) >= 0`, which is **always true** — so a caller that derived its
threshold from configuration (an empty authority list gives `0`) would accept a completely
unsigned consensus, and therefore any issuer key an attacker liked. Verified by probe
before fixing. **Fix:** both `accept_consensus` and `verify_consensus` reject a zero
threshold outright; trust decisions fail closed. A property now asserts it for arbitrary
signature sets.

### F2 — MEDIUM (fixed): secrets were not zeroized

`Blinding.blind` (the scalar whose secrecy *is* unlinkability) and `Issuer.key` were left in
memory on drop, inconsistent with `gyre-endpoint`, which already used `ZeroizeOnDrop`.
**Fix:** both types are now `ZeroizeOnDrop`, and intermediate hash buffers are wiped.

### F3 — MEDIUM (mitigated): unbounded spent set

Double-spend prevention stores every redeemed seed in a `HashSet` that grew without bound —
an attacker who acquires many tokens can exhaust memory. **Mitigation:** `rotate()` bounds
it per epoch and `spent_count()` makes it observable. **Residual risk:** nothing *forces*
rotation; an operator who never rotates still grows unboundedly. A time-based epoch policy
is not implemented.

### F4 — LOW (fixed): hash input could be ambiguous

`hash_to_point` took `&[u8]`, so `DST ‖ seed` would be ambiguous for variable-length seeds.
No caller passed anything but 32 bytes, so it was latent. **Fix:** the parameter is now
`&[u8; 32]`, making ambiguity impossible by type rather than by convention.

### F5 — INFORMATIONAL: issuer and verifier are the same party

`verify` needs the secret key, so only the issuer can redeem. This matches Privacy Pass but
rules out third-party verification. Documented, not a defect — but it means a compromised
issuer can mint tokens at will, and there is no mechanism to detect that.

### F6 — INFORMATIONAL: tokens are bearer credentials

A stolen token is usable by the thief; there is no binding to a client identity (by design —
binding would destroy unlinkability). Deployments must treat tokens as secrets in transit.

### F7 — INFORMATIONAL: spent-set lookup is not constant time

`HashSet` lookup timing may reveal whether a seed was already spent. The result is returned
to the caller anyway, so the leak is unlikely to matter — flagged for completeness.

## 6. Open questions for the auditor

Ranked by how much they would change our confidence:

1. **Q1 — Does the composition actually achieve P2 (one-more unforgeability)?** The blind
   evaluation, the DLEQ transcript, and the redemption check are individually standard; the
   *composition* has not been proven. This is the question we most want answered.
2. **Q2 — Is the custom hash-to-group sound as a random oracle?** SHA-512 →
   `from_uniform_bytes` is believed fine, but it is not the RFC's `expand_message_xmd`. Is
   there any distinguisher or bias we have missed?
3. **Q3 — Is the DLEQ transcript complete?** It binds `G, Y, B, Z, A₁, A₂`. Is anything
   missing that would enable proof reuse across sessions, epochs, or issuers?
4. **Q4 — Key distribution *(implemented — please review the design)*.** Clients now pin
   `Y` from `VerifiedParams`, obtainable only by threshold verification (§F1a). Open parts:
   is the `NetworkParams` encoding genuinely canonical, is the epoch-binding check
   sufficient, and **what should a client do with a stale consensus during key rotation** —
   today it would simply fail to verify tokens from the new epoch.
5. **Q5 — Rotation policy.** What epoch length bounds the spent set without stranding honest
   clients mid-flight? Should tokens carry an explicit epoch identifier?
6. **Q6 — Should we simply adopt an audited implementation instead?** Given D11, the honest
   default may be to replace this construction with a reviewed VOPRF library and keep only
   the integration. We would like a recommendation.

## 7. Test vectors

Reproducible vectors live in
[`tests/token_vectors.rs`](../crates/gyre-shield/tests/token_vectors.rs) and run with
`cargo test -p gyre-shield --test token_vectors`.

With issuer secret seed `000102…1e1f` and token seed `42` × 32:

| Value | Bytes (hex) |
|---|---|
| Issuer public key `Y = k·G` | `0a9a69c0ab673b88dd084370deb7a78bca331eb8d3a5dda5ec893271694f6819` |
| Token evaluation `N = k·H(seed)` | `84b9ba04b1024d71820f41fd9bead7eebd6154255e449ab29b6de862f4ddf45f` |

> [!NOTE]
> These are **self-generated regression vectors**: they pin the wire format so it cannot
> change by accident. They are *not* independent validation — nothing has cross-checked
> them against another implementation. Doing so is part of Q1/Q2.

Blinded points and DLEQ proofs are deliberately **not** fixed vectors: both incorporate
fresh randomness, and that randomness is precisely what provides unlinkability. What is
deterministic — and what the vectors pin — is the final evaluation for a given
(issuer key, token seed).

## 8. What is out of scope

The token is one mechanism inside a system with much larger, already-documented limits.
None of these are cryptographic defects and none would be fixed by an audit of this file:

- **The crowd.** Unlinkability among a handful of concurrent users is worth little,
  whatever the cryptography — see [`SIMULATION.md`](SIMULATION.md).
- **Traffic analysis.** Timing correlation of issuance and redemption is a network-layer
  attack; the token cannot address it.
- **Endpoint compromise.** A client whose device is compromised is deanonymised regardless.
- **The rest of the fabric.** Sphinx, mixing, MTD, PoW, PIR, and the directory are
  integrations of audited crates, covered by [`DESIGN.md`](DESIGN.md) and
  [`../SECURITY.md`](../SECURITY.md).

---

<sub>Reported issues: please follow [`../SECURITY.md`](../SECURITY.md) (GitHub private
vulnerability reporting). Source under review:
[`crates/gyre-shield/src/token.rs`](../crates/gyre-shield/src/token.rs).</sub>
