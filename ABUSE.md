# Acceptable Use & Abuse Policy

Gyre is a privacy-and-defense network fabric. Tools that protect privacy can be misused, and
pretending otherwise would be dishonest. This document states, plainly, what Gyre is **for**, what
it is **not** for, what an operator can and cannot control, and how to report abuse.

It is **not** legal advice. If you run Gyre infrastructure, understand your own jurisdiction.

---

## What Gyre is for

- **Protecting a system you own** — hiding a service's origin so it can't be found, targeted, or
  flooded, and pricing abusive requests at the application layer.
- **Protecting a person's traffic** from a *partial* network observer (the outbound mixer) — once a
  real crowd exists; today that half is research-grade and unaudited (see `README.md`, `docs/DEPLOY.md`).
- **Research and education** on how privacy/anti-DoS mechanisms compose — authorized testing, CTFs,
  defensive security, and reproducible measurement.

## What Gyre is not for

Do not use Gyre, or run Gyre infrastructure, to:

- Attack, intrude on, or disrupt systems you are not authorized to test.
- Distribute malware, run command-and-control, exfiltrate stolen data, or evade sanctions.
- Harass, stalk, dox, or target a private individual.
- Host or distribute child sexual abuse material, or any content illegal where you operate.
- Defraud, phish, or impersonate.

The project does not condone these uses and will not knowingly assist them.

---

## What an operator can and cannot see or control

Be clear-eyed about the trust model before you run a relay:

- **A rendezvous relay forwards opaque bytes.** By design it does not learn either endpoint's identity
  and cannot read the spliced content. This is the same property that makes Tor relays useful *and* the
  same reason operators cannot content-filter traffic they carry.
- **What an operator *can* do:** choose whether to run infrastructure at all; set admission difficulty
  and the bounds (`capacity`, timeouts, rate pricing); refuse or stop serving; keep an abuse contact and
  respond to reports; decide not to run origin/exit-adjacent roles if the legal exposure is unacceptable.
- **What an operator *cannot* do:** selectively decrypt or inspect user payloads, or distinguish
  "good" from "bad" traffic by content. If that matters for your posture, do not run the relay.

Running infrastructure that relays traffic for others carries real-world and legal implications. The
[Tor relay operator legal resources](https://community.torproject.org/relay/community-resources/) are a
useful reference point for the kinds of questions to ask, though Gyre is a different project and nothing
here is a guarantee about your situation.

---

## Honest limits (so no one is misled)

- Gyre provides **no volumetric L3/L4 DDoS defense** (decision D22) — that is a scrubber's job.
- The outbound anonymity rotor is **only as strong as a real crowd** and is **unaudited**. Do not rely
  on it for safety-critical anonymity yet.
- **Endpoint compromise deanonymises** regardless of the network.
- Gyre is **not** a tool for guaranteed, accountability-free anonymity, and it is **not** a shield from
  lawful process. It is `0.y.z` research software provided **without warranty**.

---

## Reporting abuse

- **Misuse of a Gyre deployment or the project:** open a report at
  <https://github.com/rupeshbharambe24/Gyre/issues> (or the private path in
  [`SECURITY.md`](SECURITY.md) if the report itself is sensitive). Operators who run their own Gyre
  instances should publish their **own** abuse contact and takedown process.
- **Security vulnerabilities** (not abuse) go through [`SECURITY.md`](SECURITY.md).

If you run a public Gyre relay, you are expected to provide a reachable abuse contact and to respond to
good-faith reports. "I just forward bytes" is a true statement about the protocol, not a substitute for
an operational posture.

---

## For contributors

By contributing you agree your contributions are intended to support the uses above, not to add features
whose primary purpose is to enable the prohibited uses. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
