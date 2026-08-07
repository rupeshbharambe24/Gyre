# Gyre — Cryptographic Audit Package

![status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)
![construction: RFC 9497 lib](https://img.shields.io/badge/construction-upstream%20crate-yellow.svg)
![integration: unreviewed](https://img.shields.io/badge/integration-not%20reviewed-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

What an external reviewer needs to assess the cryptography in Gyre — which, as of the
`voprf` port, is **a much smaller surface than it used to be.**

> [!WARNING]
> **Correction (2026-08-07): no crate in this stack is audited at the version we use.**
> Earlier revisions of this document called `voprf` "the audited library" and treated
> upstream crates as audited-and-therefore-out-of-scope. That was not substantiated.
> `voprf` has **no published third-party cryptographic audit**. NCC Group's
> [2021 `opaque-ke` review](https://www.nccgroup.com/research/public-report-whatsapp-opaque-ke-cryptographic-implementation-review/) covered `opaque-ke` v0.5.0, which did **not**
> depend on `voprf` — the crate was first published two months after the fieldwork. `voprf`
> was later extracted from `opaque-ke`'s inline OPRF code, and that review found real bugs
> in precisely that code, which was then rewritten against successive drafts up to RFC 9497
> and never re-reviewed. **Code lineage is not audit coverage.**
>
> `sphinx-packet` is the one partial exception, and it is worth stating exactly rather than
> rounding in either direction: its **repository** was named in the scope of a 2021 review by
> JP Aumasson, but that review predates the crate's first crates.io release by 17 months and
> three cryptographic changes, including a payload-key-derivation redesign in v0.6.0. We use
> 0.7.0. So: a real review, of code that is not the code we run.
>
> Depending on these crates remains the right call under **D11** — they are the best-reviewed
> implementations available, and the hand-rolled VOPRF that `voprf` replaced was demonstrably
> broken (F1). But a reviewer should know the layer beneath Gyre's code is largely unreviewed
> too, and size their scepticism accordingly.

> [!IMPORTANT]
> **The scope of this document shrank dramatically, on purpose.**
>
> Gyre used to contain a hand-assembled VOPRF. Reviewing it for this document found that it
> was labelled "verifiable" while carrying **no DLEQ proof**, which broke unlinkability
> outright (finding F1). Rather than keep maintaining bespoke cryptography, the construction
> was **replaced with the [`voprf`](https://crates.io/crates/voprf) crate's implementation
> of RFC 9497** (`ristretto255-SHA512`) — the same library behind OPAQUE.
>
> So the question for an auditor is no longer *"is this homemade protocol sound?"* but the
> far narrower *"is this library used correctly, and is the policy around it right?"*
> Deleting the code that needed auditing was the cheapest way to reduce risk, and it is
> what design decision **D11** asked for in the first place.

> [!CAUTION]
> **No external audit has taken place.** This is the package prepared for one. A
> self-review is the author checking their own work — precisely the thing an audit exists
> to distrust — and this project's own self-review already missed a critical flaw for
> several commits before catching it.

---

## Contents

- [1. Scope](#1-scope)
- [2. Specification](#2-specification)
- [3. Security model](#3-security-model)
- [4. Conformance to RFC 9497](#4-conformance-to-rfc-9497)
- [5. Self-review findings](#5-self-review-findings)
- [6. Open questions for the auditor](#6-open-questions-for-the-auditor)
- [7. Test vectors](#7-test-vectors)
- [8. What is out of scope](#8-what-is-out-of-scope)

---

## 1. Scope

**In scope — Gyre's remaining cryptographic surface.** Note that none of it is a *protocol*
any more; it is integration and policy around an upstream implementation.

**Size, so you can decide whether to spend the time:** ~1,010 lines of implementation across
the four files below, of which roughly 250 are cryptographically sensitive. The core is
about 60 lines: `blind()`, `unblind()`, `Issuer::verify`, `Issuer::redeem` in `token.rs`.

| Component | File | What is Gyre's own |
|---|---|---|
| Capability-token integration | `crates/gyre-shield/src/token.rs` | Key provenance, single-use set, epoch rotation, wire encodings, RNG adapter |
| Consensus parameter encoding | `crates/gyre-directory/src/params.rs` | Canonical encoding that signatures cover |
| Threshold verification | `crates/gyre-directory/src/lib.rs` | Quorum + epoch-binding checks |
| QUIC certificate pinning | `crates/gyre-net/src/quic.rs` | The `ServerCertVerifier` implementation |

**Not in scope — upstream crates used as-is (D11).** Not because they are audited — see the
correction above, and the audit-provenance note in [`../SECURITY.md`](../SECURITY.md) — but
because reviewing them is a different and much larger job than reviewing Gyre. The honest
one-line summary of the tree beneath us: `sphinx-packet`'s **repository** was reviewed by
JP Aumasson in 2021, 17 months before its first release and three cryptographic changes ago;
`voprf` has no published audit; the rest are widely-used but unaudited-for-our-purposes:

`voprf` (RFC 9497 VOPRF — **the construction itself**) · `sphinx-packet` (onion format) ·
`curve25519-dalek` · `x25519-dalek` · `ed25519-dalek` · `rustls` (TLS 1.3) · `sha2` ·
`hmac` · `reed-solomon-erasure` · `zeroize`

## 2. Specification

The protocol is **RFC 9497 VOPRF mode, ciphersuite `ristretto255-SHA512`**, as implemented
by the `voprf` crate. It is not restated here — read the RFC, which is the authority. What
follows is what Gyre wraps around it.

### 2.1 The flow

```text
Client                                    Issuer (secret k, published Y = k·G)
------                                    ------------------------------------
seed ←$ {0,1}^256
(state, B) = VoprfClient::blind(seed)   ──── B ───▶
                                          (Z, π) = VoprfServer::blind_evaluate(B)
                                        ◀── Z, π ───
output = state.finalize(seed, Z, π, Y)
   └─ verifies the DLEQ proof π against Y; fails closed on mismatch
token = (seed, output)

--- later, unlinkably ---
                                        ── seed,output ──▶
                                          accept iff  VoprfServer::evaluate(seed) == output
                                          (constant-time)  and seed ∉ spent
                                          then spent ∪= {seed}
```

### 2.2 What Gyre adds, and why each piece exists

| Piece | Why it is Gyre's problem, not the library's |
|---|---|
| `PublicKey::from_verified_params` | The RFC says verify against the server's public key; it does not say *where that key comes from*. Getting it from the issuer would make the proof worthless. |
| `VerifiedParams` (in `gyre-directory`) | Makes "this key was published by a quorum" a *type*, so an unverified key cannot reach `unblind` by accident. |
| Spent set + `rotate()` | The RFC has no notion of single use or epochs. Both are deployment policy. |
| Fixed-width wire encodings | `ELEMENT_LEN=32`, `PROOF_LEN=64`, `OUTPUT_LEN=64`, asserted by a test so an upstream change breaks loudly. |
| `OsCsprng` adapter | `voprf` is generic over `RngCore + CryptoRng`; this forwards to `getrandom`. It invents no randomness. |

### 2.3 Key derivation

`Issuer::from_secret_seed` uses the RFC's `DeriveKeyPair` via `VoprfServer::new_from_seed`,
with info string `gyre-capability-token-v2/issuer-key`. An operator must be able to reload
the same key after a restart, or every restart silently invalidates live tokens.

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

P1 depends on P4, and that dependency is exactly what the hand-rolled version got wrong
(F1). P1, P2 and P4 now rest on RFC 9497's analysis rather than on anything argued here —
which is the whole benefit of the port. **P3 (single use) is still Gyre's**: it comes from
the spent set, not from the OPRF, and an auditor should treat it as unproven code rather
than inherited theory.

**Anonymity-set caveat.** P1 is unlinkability *within the set of tokens issued in the same
epoch and redeemed in the same window*. If one client is the only redeemer in a window, the
timing links it regardless of the cryptography. That is the crowd constraint that governs
the whole project, not a property the token can fix.

## 4. Conformance to RFC 9497

**The construction now *is* RFC 9497** — `voprf` implements the specification, including
`expand_message_xmd` hash-to-group with the RFC's DSTs, the standard DLEQ transcript, and
`DeriveKeyPair`. The long list of deviations that used to live here is gone, because the
code that deviated is gone.

For the record, what the hand-rolled version got wrong and the library gets right:

| Area | Old hand-rolled version | Now (`voprf`) |
|---|---|---|
| Mode | base OPRF, mislabelled "VOPRF" — **no proof at all** | true VOPRF with DLEQ proof |
| Hash-to-group | bare SHA-512 → `from_uniform_bytes` | RFC `expand_message_xmd` with the specified DST |
| DSTs | custom `gyre-capability-token-v1/*` | RFC-specified, versioned |
| Proof transcript | custom Chaum–Pedersen encoding | RFC encoding |
| Interoperability | none | an independent RFC 9497 implementation can interoperate |
| Analysis inherited | none | the RFC's, plus the library's review history |

**Remaining deviation:** the *token* is `(seed, output)` and redemption recomputes
`evaluate(seed)`. That is a Gyre-level protocol on top of the OPRF, not part of the RFC,
and it is what §3's properties P2/P3 actually rest on.

## 5. Self-review findings

Found by reviewing the (then hand-rolled) code against RFC 9497 while preparing this
document. **F1 was critical.** Several of these are now moot *because the code they applied
to no longer exists* — that is recorded rather than deleted, because the history is the
strongest argument for why the port happened.

| Finding | Status after the `voprf` port |
|---|---|
| F1 — no DLEQ proof, unlinkability broken | **Fixed twice**: first by hand, then removed entirely by delegating to the library |
| F1a — key distribution (was Q4) | **Still Gyre's**, still in scope |
| F2 — secrets not zeroized | **Moot** — `VoprfClient`/`VoprfServer` are `ZeroizeOnDrop` upstream |
| F3 — unbounded spent set | **Still Gyre's**, mitigated by `rotate()` |
| F4 — hash-input ambiguity | **Moot** — the RFC's encoding is unambiguous |
| F5/F6/F7 — issuer==verifier, bearer tokens, spent-set timing | **Still Gyre's**, informational |
| F8 — `accept_consensus` accepted unsigned docs at threshold 0 | **Fixed**, unrelated to the port |


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

### F18 — HIGH (fixed): `build_is_blessed` had the *same* zero-threshold fail-open as F8

**Found while preparing this document for external review**, by checking whether every
threshold comparison in the crate carried the F8 guard rather than trusting that the fix had
been applied wherever it applied. It had not: `build_is_blessed`
(`crates/gyre-directory/src/lib.rs`) still computed `distinct_valid_signers(...) >= threshold`
with no guard — in the *same file*, 99 lines below the F8 fix.

Verified by probe before fixing, not inferred:

```text
build_is_blessed(unknown hash, NO sigs, NO rebuilders, threshold=0) = true
```

So an unsigned, unknown build hash was reported as **blessed**. Build attestation is the
weaker of the two trust mechanisms to begin with — it proves `binary == source`, never what
a relay is actually running — and a fail-open version of it is worth less than nothing: it
reports agreement no rebuilder ever expressed.

**Fix:** the same fail-closed guard, plus a regression test with a negative control (a
genuinely signed hash must still bless at threshold 1, so the test cannot pass by the
function simply refusing everything).

> **The lesson is the finding.** F8 was recorded as fixed and this document said so. One
> instance was fixed; the *class* was not swept. When a fail-open is found, grep for every
> comparison of the same shape before calling it closed.

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

### F9–F13 — from the post-port adversarial review

A three-lens adversarial review of the ported code (security properties, correct `voprf`
usage, test integrity) raised 27 observations. **Thirteen were serious enough to verify
individually, and all thirteen were refuted** — unlinkability, key pinning and
panic-reachability were checked against the code and found sound. What survived was a set
of smaller issues. These were fixed:

- **F9 — `Blinding`'s doc comment claimed the struct was wiped on drop; the seed was not.**
  A documentation/code mismatch in exactly the direction this project treats as a defect.
  Fixed: `Blinding` now derives `ZeroizeOnDrop`, and the comment describes what the code
  does.
- **F10 — `Token` derived `Copy` and `PartialEq`.** `Copy` makes a bearer credential
  impossible to wipe reliably, and a *derived* `PartialEq` is a non-constant-time
  comparison of the very secret the module compares carefully in `verify` — a trap sitting
  next to the careful version. Fixed: `Copy` removed, `PartialEq` implemented in constant
  time.
- **F11 — the constant-time comparison was hand-rolled** while `subtle` was already in the
  dependency graph via `voprf`. A hand-written branchless fold has no barrier stopping a
  compiler from reintroducing a branch. Fixed: delegated to `subtle::ConstantTimeEq`.
- **F12 — `OsCsprng::try_fill_bytes` panicked instead of returning `Err`**, making the
  fallible half of the API a lie to any caller that checked it. Fixed.
- **F13 — two weak tests.** The key-partitioning test had **no negative control**, so it
  could not distinguish "pinning rejected a foreign key" from "the rogue's responses were
  malformed and would fail against any key"; and a property generated a value it never
  used. Both fixed — the control now asserts the rogue's proof *does* verify against the
  rogue's *own* key, so the refusals are provably caused by the key mismatch.

### F14–F17 — known gaps, not fixed

Recorded rather than quietly dropped. None is a defect in the cryptography; each is a real
limitation an auditor should know about.

- **F14 — `Issuer::issue` is an unauthenticated issuance oracle.** Nothing in this module
  binds issuance to the proof-of-work admission it is documented to reward. Anyone who can
  reach the issuer can obtain unlimited tokens. The binding is deployment plumbing that
  does not exist yet, and until it does the token grants no scarcity.
- **F15 — `rotate()` has no caller anywhere in the repository.** The bound on the spent set
  is therefore theoretical: nothing schedules an epoch. See Q-D.
- **F16 — `Issuer::evaluate` is a public token-minting helper.** It requires the secret key,
  so it grants nothing a caller holding the `Issuer` does not already have — but it is a
  footgun, and it exists for test-vector generation.
- **F17 — panics on RNG or key-generation failure are an undocumented availability
  surface.** They are the *correct* behaviour (never continue with a broken CSPRNG), but a
  relay that aborts is a relay that is down.

## 6. Open questions for the auditor

The port answered most of the old list — Q1 (is the composition sound?), Q2 (is the
hash-to-group sound?), Q3 (is the transcript complete?) and Q6 (should we adopt a library?)
are all resolved by using the RFC implementation. What remains is narrower and, we think,
more answerable:

1. **Q-A — Is the library used correctly?** Ciphersuite choice, argument order, that
   `finalize` really is the proof-verifying call, and that the same input reaches both
   `blind` and `finalize`. A mismatch would produce tokens that silently never verify.
2. **Q-B — Is `(seed, output)` a sound token?** Redemption reveals the OPRF input and
   output. Does revealing both weaken anything, and is the constant-time comparison in
   `verify` sufficient to stop byte-at-a-time forgery?
3. **Q-C — Key distribution.** Clients pin `Y` from `VerifiedParams`. Is the
   `NetworkParams` encoding genuinely canonical, is the epoch-binding check sufficient, and
   **what should a client do with a stale consensus during key rotation** — today it simply
   fails to verify tokens from the new epoch.
4. **Q-D — Rotation policy.** What epoch length bounds the spent set without stranding
   honest clients mid-flight? Should tokens carry an explicit epoch identifier?
5. **Q-E — The QUIC certificate verifier.** `gyre-net::quic` implements a custom
   `rustls::ServerCertVerifier` that pins a SHA-256 fingerprint and delegates signature
   checking. Custom verifiers are a classic source of silent authentication bypass — this
   one deserves a careful read.
6. **Q-G — RFC conformance of the vectors.** The vectors pin *Gyre's* output, not RFC 9497
   conformance. Cross-checking against the RFC's own published test vectors would prove
   interoperability; the reviewer suggests `voprf`'s `danger` feature (scoped to
   dev-dependencies) may expose what that needs.
7. **Q-F — Dependency duplication.** `voprf 0.5` pins `sha2 0.10` and an older
   `curve25519-dalek` while the workspace uses newer ones, so both versions are linked. Is
   that acceptable, or should the workspace align (possibly on `voprf 0.6-pre`)?

## 7. Test vectors

Reproducible vectors live in
[`tests/token_vectors.rs`](../crates/gyre-shield/tests/token_vectors.rs); run with
`cargo test -p gyre-shield --test token_vectors`.

With issuer secret seed `000102…1e1f` (info `gyre-capability-token-v2/issuer-key`) and token
seed `42` × 32:

| Value | Bytes (hex) |
|---|---|
| Issuer public key `Y` | `fefc48110bde263d480b1e2458f0a7703ed056e97e5af8c2eae4186dc056cd55` |
| OPRF output for the token seed | `6e01c3142b251bd1f7a675b8b3fab6b6190ce2d49b9c2b667ea48b8b02a6ee84`<br>`7e77822ecf796e90f636f11613586f324784618b30083d93306d447fcd5ef151` |

> [!NOTE]
> **These values changed when the construction was replaced**, and that was intentional —
> the old encoding was never deployed. They are **self-generated regression vectors**: they
> pin the wire format against accidental change, but nothing has cross-checked them against
> another RFC 9497 implementation. Doing so is part of Q-A, and is now *possible* precisely
> because the implementation is conformant.

Blinded elements and proofs are deliberately **not** fixed vectors: both incorporate fresh
randomness, and that randomness is what provides unlinkability. What is deterministic — and
what the vectors pin — is the final output for a given (issuer key, token seed).

## 8. What is out of scope

The token is one mechanism inside a system with much larger, already-documented limits.
None of these are cryptographic defects and none would be fixed by an audit of this file:

- **The crowd.** Unlinkability among a handful of concurrent users is worth little,
  whatever the cryptography — see [`SIMULATION.md`](SIMULATION.md).
- **Traffic analysis.** Timing correlation of issuance and redemption is a network-layer
  attack; the token cannot address it.
- **Endpoint compromise.** A client whose device is compromised is deanonymised regardless.
- **The rest of the fabric.** Sphinx, mixing, MTD, PoW, PIR, and the directory are
  integrations of upstream crates, covered by [`DESIGN.md`](DESIGN.md) and
  [`../SECURITY.md`](../SECURITY.md).

---

<sub>Reported issues: please follow [`../SECURITY.md`](../SECURITY.md) (GitHub private
vulnerability reporting). Source under review:
[`crates/gyre-shield/src/token.rs`](../crates/gyre-shield/src/token.rs).</sub>
