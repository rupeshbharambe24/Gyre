# Community Crypto Review — ready-to-send messages

> Copy-paste outreach for getting Gyre's cryptography reviewed, for free, by the community.
> The *why*, scope, and threat model live in [`REVIEW-ASK.md`](REVIEW-ASK.md); this file is the
> **literal send-list** — each message is composed and ready. Send in the order below.
>
> **Golden rule:** these are *narrow, answerable* questions about one small module, never "please
> review my whole scheme." That framing is what gets answers instead of silence.

## Send order & checklist

- [ ] **1.** Crypto Stack Exchange — Q1 (key-partitioning / unlinkability) ← the one that matters most
- [ ] **2.** Crypto Stack Exchange — Q2 (metadata binding) *(wait a day or two after Q1)*
- [ ] **3.** Crypto Stack Exchange — Q3 (single-use across key rotation)
- [ ] **4.** GitHub issue on `facebook/voprf`
- [ ] **5.** Email OTF Security Lab (`security_lab@opentech.fund`)
- [ ] **6.** Email CFRG (`cfrg@irtf.org`)

After each, drop the link/thread back into the repo (an issue or a `docs/REVIEW-LOG.md`) so reviewers
and future-you can see what's outstanding.

---

## 1 · Crypto Stack Exchange — Q1 (post this first)

**Title:** `Does a DLEQ-verified VOPRF with an out-of-band-pinned server key prevent issuer key-partitioning?`

**Tags:** `oprf` `unlinkability` `anonymity` `zero-knowledge-proofs`

**Body:**
> In a verifiable VOPRF (RFC 9497, ristretto255-SHA512) used to build unlinkable single-use tokens, the
> client verifies a Chaum–Pedersen DLEQ proof at *unblind* time against a server public key `P`. In my
> setup the client **pins `P` from an external, signed document** (not from the issuer), then unblinds
> against that pinned `P`.
>
> My claim is that this defeats issuer **key-partitioning** — a malicious issuer handing each client a
> *different* key and then, at redemption, trying each key to re-identify who redeemed.
>
> Questions:
> 1. Does verifying the DLEQ against a single pinned `P` fully prevent partitioning, or is there a
>    residual requirement that **all honest clients pin the same `P`** — and if so, is "same" a
>    cryptographic property or purely a consistency assumption on the pinned value?
> 2. If the pinned-key document is itself only *threshold-signed* (not unique per epoch), can an
>    equivocating signer still partition clients by key?
>
> I'm asking specifically about the unlinkability property, not the one-more-token unforgeability.

---

## 2 · Crypto Stack Exchange — Q2

**Title:** `RFC 9497 POPRF: risks of binding attacker-influenced metadata (info) into the evaluation?`

**Tags:** `oprf` `rfc` `unlinkability`

**Body:**
> I use a partially-oblivious PRF (RFC 9497) and bind public metadata (`info`) into the evaluation — in
> my case an **epoch identifier**, so tokens are only valid within one key epoch.
>
> If the `info` is attacker-chosen or crosses epochs, does it open any **unlinkability** or
> **one-more-token forgery** risk beyond what the base VOPRF already covers? And is there a
> canonical-encoding pitfall I should guard against when `info` is application-controlled?

---

## 3 · Crypto Stack Exchange — Q3

**Title:** `Single-use anonymous token: is a replay window opened when the spent set is pruned at key rotation?`

**Tags:** `oprf` `anonymity` `replay-attack`

**Body:**
> An anonymous token (verifiable VOPRF) is single-use, enforced by a server-side spent set. To bound the
> set's growth, the issuer **rotates its key each epoch** and prunes the spent set on rotation.
>
> At the rotation boundary: is a token minted in epoch `N` already rejected in epoch `N+1` **purely by
> key mismatch** (the DLEQ/finalize no longer verifies against the new key), or do I need an explicit
> **epoch tag** on the token to avoid a replay window opening exactly when the spent set is pruned? What
> is the standard way to bound spent-set growth without that window?

---

## 4 · GitHub issue — `facebook/voprf` (Issues, not Discussions)

**Title:** `Verifiable mode to defeat issuer key-partitioning — is out-of-band-pinning the server PublicKey the intended pattern?`

**Body:**
> I'm using `voprf` in **verifiable mode** to build unlinkable single-use tokens. Clients obtain the
> server `PublicKey` from a **signed external document** (not from the issuer) and call `finalize`/unblind
> with that pinned key, so a malicious issuer can't hand each client a distinct key and re-identify them
> at redemption.
>
> 1. Is out-of-band-pinned `PublicKey` the intended way to get this property, or does the API already
>    assume the key is authenticated by the caller?
> 2. If the pinned key and the proof's key disagree, is `finalize` **always** an `Err` (never a silent,
>    linkable success)? Any footgun in `blind_evaluate` / `finalize` I should know about?
>
> (RFC 9497, ristretto255-SHA512. Context: an MIT-licensed research fabric; I'm trying to use the crate
> *correctly*, not re-implement it.)

---

## 5 · Email — OTF Security Lab

**To:** `security_lab@opentech.fund`
**Subject:** `Free design-review request — anonymous-token unlinkability in a small Rust module`

**Body:**
> Hello OTF Security Lab,
>
> I maintain **Gyre**, an MIT-licensed, open-source privacy/anti-DoS network fabric in Rust. I'd be
> grateful for a scoped look at **one small, security-critical module**: an anonymous capability token
> built on the `voprf` crate (RFC 9497, verifiable mode, ristretto255-SHA512).
>
> **The one question that matters:** does the token preserve *unlinkability at redemption* as I use it?
> The client blinds, the issuer evaluates with a DLEQ proof, and the client verifies that proof against a
> public key it pins from a threshold-signed consensus. I fixed an earlier version that shipped *no* DLEQ
> proof and demonstrably linked 5/5 clients; I want to know whether the fix is actually sound and whether
> pinning a single key is sufficient.
>
> **Scope:** `crates/gyre-shield/src/token.rs`, ~660 lines (~250 crypto-sensitive). Repro:
> `git clone https://github.com/rupeshbharambe24/Gyre && cargo test -p gyre-shield`. Threat model and
> open questions are in `docs/AUDIT.md`; a 30-minute on-ramp is in `docs/REVIEW-ASK.md`.
>
> Could you let me know whether this fits the Security Lab's scope before I file a formal application?
> Thank you for the work you do.
>
> — Rupesh Bharambe · github.com/rupeshbharambe24/Gyre

---

## 6 · Email — CFRG (IRTF, not IETF)

**To:** `cfrg@irtf.org`
**Subject:** `Sanity-check request: VOPRF (RFC 9497) key-pinning to prevent issuer partitioning`

**Body:**
> Hello CFRG,
>
> Short, concrete question from an open-source implementation (not a draft proposal).
>
> **Threat model:** a malicious token *issuer* that wants to de-anonymise redeemers. It may hand different
> clients different keys (key-partitioning). The network adversary is separate and out of scope here.
>
> **Construction:** verifiable VOPRF (RFC 9497, ristretto255-SHA512). Clients pin the server public key
> from a threshold-signed consensus document and verify the issuer's DLEQ proof at unblind time against
> that pinned key.
>
> **Question:** is DLEQ-verification against an out-of-band-pinned key sufficient to defeat
> key-partitioning, assuming all honest clients pin the *same* key? Is "all honest clients pin the same
> key" a purely cryptographic guarantee here, or does it reduce to a consensus/equivocation assumption on
> the pinned value?
>
> Code + full threat model: https://github.com/rupeshbharambe24/Gyre (`docs/AUDIT.md`). One module,
> ~250 crypto-sensitive lines; happy to point to exact functions.
>
> Thank you,
> Rupesh Bharambe

---

## Do-not-send (verified dead ends)
tor-dev / tor-relays (Tor's own codebase only — reads as spam), IACR ePrint (wants novelty), arXiv
(needs endorsement), `moderncrypto.org` and `lists.randombit.net` (dead hosts). PoPETs is for a *paper*,
much later.
