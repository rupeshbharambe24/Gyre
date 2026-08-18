# Reviewing Gyre's cryptography — a short on-ramp

Gyre is a two-rotor privacy/DoS fabric. Its one piece of genuinely security-critical,
homegrown *policy* is the **anonymous capability token** (`crates/gyre-shield/src/token.rs`)
and the **admission gate** it is bound to (`crates/gyre-shield/src/admission.rs`). The
underlying VOPRF primitive is the maintained [`voprf`](https://github.com/facebook/voprf)
crate (RFC 9497, ristretto255-SHA512); what we wrote is the *usage* and the *policy* around it:
blinding/unblinding with a DLEQ check, key-pinning from a threshold-signed consensus,
a single-use spent set, epoch rotation, and binding token issuance to a solved proof-of-work.

**Nothing in this tree has had an external cryptographic review. That is precisely what this
document asks for** — not a rubber stamp, an adversarial read of a small, well-scoped surface.
The full package is [`docs/AUDIT.md`](AUDIT.md) (~490 lines); this file is the ~30-minute
on-ramp so a volunteer never has to read that first.

This document is meant to be *copy-pasted* into the right venue. Pick the block, send it.

---

## 1 · The ~200-word ask (for an email or mailing list)

> **Subject: Free review request — anonymous-token unlinkability in a small Rust module**
>
> I maintain Gyre, an MIT-licensed privacy/anti-DoS network fabric in Rust. I'd be grateful
> for an adversarial read of one small, security-critical module: an anonymous capability
> token built on the `voprf` crate (RFC 9497, verifiable/POPRF mode, ristretto255-SHA512).
>
> **The one question that matters:** does the token preserve *unlinkability at redemption*
> as I use it? The client blinds, the issuer evaluates with a DLEQ proof, and the client
> verifies that proof at unblind time against a public key it pins from a threshold-signed
> consensus document. My claim is that this defeats issuer **key-partitioning** (a malicious
> issuer handing each client its own key to re-identify them at redemption). I fixed an
> earlier version that shipped *no* DLEQ proof and demonstrably linked 5/5 clients; I want to
> know whether the fix is actually sound, and whether pinning a *single* key is sufficient.
>
> **Scope:** `crates/gyre-shield/src/token.rs`, ~660 lines, of which ~250 are crypto-sensitive
> (`blind`, `unblind`, `Issuer::issue`, `redeem`). Repro: `git clone …/Gyre && cargo test -p
> gyre-shield`. Reading it is ~30–60 min for the focused question, ~2–3 h for the whole
> module. Threat model and open questions are in `docs/AUDIT.md`.
>
> Reply here, or open an issue at github.com/rupeshbharambe24/Gyre. Thank you.

---

## 2 · Three narrow questions for Crypto Stack Exchange

Crypto Stack Exchange's rule is explicit: **"peer review of your full cryptographic scheme,
here is not the place."** So do *not* post "review my token." Post these one at a time, each
self-contained, each answerable without the codebase:

**Q1 — the crown jewel (unlinkability vs. key-partitioning):**

> In a verifiable VOPRF (RFC 9497), the client verifies a Chaum–Pedersen DLEQ proof at unblind
> time against a server public key `P`. If the client pins `P` from an external, signed source
> rather than learning it from the issuer, does verifying the DLEQ against that single pinned
> `P` fully prevent an issuer from *partitioning* clients — i.e. issuing to different clients
> under different keys and then, at redemption, trying each key to re-identify who redeemed?
> Or is there a residual requirement that all honest clients pin the *same* `P`, and if so, is
> that a cryptographic property or purely a consistency/gossip assumption on the pinned value?

**Q2 — metadata binding (`info` / context string):**

> RFC 9497 lets a POPRF bind public metadata (`info`) into the evaluation. If I bind an epoch
> identifier into `info` so that tokens are only valid within one key epoch, does an
> attacker-chosen or cross-epoch `info` open any unlinkability or one-more-token forgery risk
> beyond what the base VOPRF already covers? Is there a canonical-encoding pitfall I should
> worry about when the `info` is application-controlled?

**Q3 — single-use enforcement across key rotation:**

> An anonymous token is single-use, enforced by a server-side spent set. To bound that set's
> growth the issuer rotates its key each epoch and prunes the spent set on rotation. At the
> rotation boundary, is a token from epoch N already rejected in epoch N+1 purely by key
> mismatch (the DLEQ/finalize no longer verifies), or do I need an explicit epoch tag on the
> token to avoid a replay window opening exactly when the spent set is pruned?

---

## 3 · One focused issue for `facebook/voprf`

The crate's GitHub **Issues** (not Discussions — it has ~zero activity) is the right place for a
usage question the maintainers can answer quickly:

> **Using verifiable mode to defeat issuer key-partitioning — is pinning the server public key
> out-of-band the intended pattern?**
>
> I'm using `voprf` in verifiable mode to build unlinkable single-use tokens. Clients obtain the
> server `PublicKey` from a *signed external document*, not from the issuer, and call
> `finalize`/unblind with that pinned key so a malicious issuer can't hand each client a distinct
> key and re-identify them at redemption. Is out-of-band-pinned `PublicKey` the intended way to
> get this property, or does the API already assume the key is authenticated by the caller? Any
> footgun in `blind_evaluate` / `finalize` if the pinned key and the proof's key disagree — is
> that always an `Err`, never a silent linkable success? (RFC 9497, ristretto255-SHA512.)

---

## 4 · Where to send what (free venues, in order)

| Order | Venue | Send | Notes |
|-------|-------|------|-------|
| 1 | **Crypto Stack Exchange** | Q1, then Q2, Q3 (separately) | Best first venue. Narrow questions only; never "review my scheme." |
| 2 | **`facebook/voprf` GitHub Issues** | The §3 issue | Fast, specific, from the people who wrote the crate. |
| 3 | **OTF Security Lab** — `security_lab@opentech.fund` | A short scoping email first (the §1 ask trimmed) | Real, free, no credit card; does "security architecture and design reviews." Email to scope *before* any formal application. |
| 4 | **CFRG** — `cfrg@irtf.org` (via mailman.irtf.org — **IRTF, not IETF**) | The §1 ask + a tight threat model | One-shot; write the threat model first or it reads as noise. |
| 5 | **PoPETs** (petsymposium.org) | Only if this grows into a paper | Free — no fees, no travel. Rolling quarterly deadlines. Much later. |

**Do not post to** (verified dead ends): tor-dev / tor-relays (Tor's own codebase only — reads as
spam), IACR ePrint (wants novelty), arXiv (needs endorsement), OSS-Fuzz (needs a large user base).
**Dead hosts** (no response at all): `moderncrypto.org`, `lists.randombit.net`.

---

## 5 · Provenance a reviewer should know up front

Be honest about assurance so no one wastes time on a false premise:

- **`voprf` has no published audit.** It was *extracted* from `opaque-ke`, whose v0.5.0 got a
  2021 NCC Group review — but that review predated `voprf`'s first release, NCC found bugs in
  exactly the inline OPRF code that later became `voprf`, and the extracted crate was then
  rewritten for RFC 9497 and never re-reviewed. **Code lineage ≠ audit coverage.**
- **`sphinx-packet` (used elsewhere in Gyre, not in the token) has no audited *release*.** A 2021
  JP Aumasson review covered the `nymtech/sphinx` repo 17 months before its first crates.io
  release, and there have been crypto changes since (a payload-key-derivation redesign in v0.6.0;
  we use 0.7.0).
- So the primitives are *reasonable, maintained choices* — but the released versions we ship are
  unreviewed, and the **policy layer around them is homegrown.** That layer is what this ask is
  about.

---

## 6 · Two commands to reproduce

```sh
git clone https://github.com/rupeshbharambe24/Gyre && cd Gyre
cargo test -p gyre-shield          # runs the token unit tests + the token_unlinkability integration test
cargo run  -p gyre-shield          # live demo: mints a token against a 3-of-4 threshold-signed key,
                                   # issuer sees only a blinded point, client verifies the DLEQ proof
```

The unlinkability test to read first is `a_key_partitioning_issuer_cannot_tag_any_client` in
`crates/gyre-shield/tests/token_unlinkability.rs` — it asserts that a rogue issuer's per-client key
**does** verify against its *own* key (the negative control, so the test can actually fail) yet
cannot link a client who pinned the honest consensus key. That test is the whole claim in one file.
