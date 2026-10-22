# Deploying the Gyre Shield (live)

How to run Gyre's **inbound rotor** — the guarded rendezvous relay + origin-hiding — as a real service
on the public internet. This is the half of Gyre that **works with zero crowd**, so it's the part you
can put live and get value from today.

> [!IMPORTANT]
> **What you can deploy, and what you can't — read this first.**
>
> - ✅ **The Shield (this doc).** Origin-hiding + L7 DoS admission gate. TCP-based, useful to **one**
>   user, honest to run today.
> - ❌ **The Mixer for real anonymity.** The outbound person-anonymity rotor is **only as strong as a
>   real crowd**, which is ~0 at launch. **Do not tell anyone to rely on Gyre for anonymity yet.** The
>   data plane runs, but with no crowd it protects no one — and the crypto is **unaudited** (see
>   [`docs/REVIEW-ASK.md`](REVIEW-ASK.md)). Deploy the Shield; grow toward the Mixer.
>
> **Honest ceilings that still apply** (decision **D22**): the Shield does **nothing** against a
> volumetric L3/L4 flood that saturates your link — that's a scrubber's job. It removes your origin as a
> target and prices L7 requests. Put a scrubber in front if you need volumetric absorption; Gyre
> complements one, it doesn't replace it.

---

## 1 · What "the Shield" gives you

- Your **origin dials out** and parks behind a relay — it binds **no inbound address**, so there's
  nothing for an attacker to find or flood directly.
- Every connection to the relay must solve a **server-issued, expiring, single-use, load-scaled
  proof-of-work** before it can park or splice. A flood of connections that skip it is refused; a client
  that pays the work gets through.
- Bounds that hold under load: capacity cap, in-flight-handshake cap, slowloris timeout, cookie-length
  cap, parked-TTL reaper, splice-lifetime timeout, AIMD rate-adaptive pricing.

---

## 2 · Prerequisites

1. **A reachable host.** The relay is **TCP** (not the library-only QUIC), so it just needs one open TCP
   port the public internet can reach. Options, zero-budget first:
   - **Your own machine with native IPv6** (most home ISPs now give this). Check:
     ```bash
     curl -6 -s https://ifconfig.co    # prints your public IPv6 → you're reachable
     ```
     If that returns an address, you can run the relay on it (open the port in your firewall).
   - **A free TCP tunnel for a demo** (e.g. an `ngrok tcp` endpoint) — fine for showing it off, not for
     a durable service.
   - A small VPS if you ever have one. (There is **no free UDP host** anywhere — but the Shield is TCP,
     so that constraint doesn't bite here; it only blocks the QUIC mixer.)
2. **Rust** (stable, MSRV 1.85) to build, or copy a release binary to the host.

---

## 3 · Build

```bash
git clone https://github.com/rupeshbharambe24/Gyre && cd Gyre

# Default build — pure MIT, SHA-256 admission puzzle:
cargo build --release -p gyre-cli
#   → target/release/gyre-rendezvous, gyre-origin, gyre-reach

# OR, for the memory-hard Equi-X puzzle (narrows a GPU/ASIC attacker's edge).
# NOTE: this pulls in the LGPL-3.0 equix/hashx crates — a licence choice for your build.
cargo build --release -p gyre-cli --features equix
```

## 4 · Run the relay (on the reachable host)

```bash
./target/release/gyre-rendezvous \
  --listen 0.0.0.0:9500 \        # or [::]:9500 for IPv6
  --capacity 1024 \             # max parked connections (also the load signal)
  --max-inflight 256 \          # concurrent admission handshakes
  --handshake-timeout-secs 10 \ # slowloris bound
  --ttl-secs 30 \               # challenge lifetime
  --parked-ttl-secs 60 \        # evict a park that never meets a peer
  --max-cookie-len 128 \
  --stats-secs 5                # heartbeat: parked count + effort load
# Add --pow equix for the memory-hard gate (requires the --features equix build above).
```

The banner states the algorithm and the ceilings. `--pow equix` **refuses to start** unless the binary
was built with `--features equix` (otherwise the gate would reject everyone — fail-closed by design).

## 5 · Run as a service (systemd)

`/etc/systemd/system/gyre-rendezvous.service`:
```ini
[Unit]
Description=Gyre guarded rendezvous relay (inbound shield)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/gyre/gyre-rendezvous --listen [::]:9500 --capacity 1024 --max-inflight 256 --stats-secs 30
Restart=on-failure
RestartSec=2
# Hardening — the relay needs no special privileges and touches no disk.
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now gyre-rendezvous
journalctl -u gyre-rendezvous -f
```

## 6 · Connect your service through it

On the machine that runs your actual service (the **origin** — it never exposes an inbound port):
```bash
./target/release/gyre-origin \
  --rendezvous <relay-host>:9500 \
  --cookie "a-long-random-shared-secret" \
  --reply "hello from the hidden origin" \
  --auth                      # mutual challenge-response (closes the bearer-cookie hijack race)
# Park across several relays for flood-dilution: repeat --rendezvous host:port.
```

A client reaches it with the **same cookie**:
```bash
./target/release/gyre-reach \
  --rendezvous <relay-host>:9500 \
  --cookie "a-long-random-shared-secret" \
  --message "ping" \
  --auth
```

Verify the gate refuses a flood (no proof-of-work):
```bash
./target/release/gyre-reach --rendezvous <relay-host>:9500 --flood 50
# → all 50 refused; the relay's --stats-secs heartbeat shows parked stays bounded.
```

## 7 · Operational posture — the honest knobs

- **The cookie is a bearer secret.** Anyone who learns it can reach the origin. Use a long random value,
  share it out-of-band, rotate it. `--auth` adds a mutual challenge-response so a leaked *relay-visible*
  value alone can't hijack the session — but leaking the cookie itself is unavoidable (it's the shared
  secret).
- **SHA-256 is the default puzzle.** It's ASIC/GPU-friendly, so a hardware attacker clears it faster than
  an honest phone. Use `--pow equix` (memory-hard) if that matters for your threat model.
- **No volumetric defense.** A flood that saturates the link wins before the puzzle is read. Front it
  with a scrubber if you need that; Gyre's job is removing the target and pricing L7.
- **The Sphinx mix relay is separate** and remains ungated — this doc is only about the inbound Shield.

## 8 · Abuse & legal — decide your posture before you publish

Running infrastructure that hides origins and relays traffic has real-world and legal implications. Have
a clear, written stance *before* you invite others:
- **State the intended use** (defensive origin-hiding / your own services / authorized research) and what
  you will not knowingly host.
- **Relay operators forward opaque bytes** — know your jurisdiction's posture on that (Tor's relay
  legal-FAQ precedents are a useful reference point).
- Add an **abuse contact** and a takedown/response process. Your `SECURITY.md` already covers vuln
  reporting; add an abuse path too.

## 9 · Smoke-test checklist

- [ ] `curl -6 -s https://ifconfig.co` (or your public IPv4/tunnel) confirms the host is reachable.
- [ ] Relay starts; banner shows the algorithm + `capacity`.
- [ ] `gyre-origin` parks (relay heartbeat shows parked ≥ 1).
- [ ] `gyre-reach` with the cookie gets the reply **across the public internet** (not localhost).
- [ ] `gyre-reach --flood 50` is fully refused and parked stays bounded.
- [ ] (If used) `--pow equix` refuses to start on a non-`--features equix` build.
