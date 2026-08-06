# Shadow simulation scaffolding

> [!CAUTION]
> **Nothing in this directory has been executed.** [Shadow](https://shadow.github.io) is
> **Linux-only** — it works by intercepting syscalls — and the machine that produced
> [`docs/SIMULATION.md`](../../docs/SIMULATION.md) runs macOS. These files are a prepared
> starting point for whoever runs it on Linux first, not a result. Do not cite them as one.

## Why Shadow, given we already have `gyre-sim`

[`gyre-sim`](../../crates/gyre-sim) drives the real protocol code but models the network:
no TCP, no congestion, no queueing. Shadow closes exactly that gap — it runs **real,
unmodified binaries** against a simulated network stack with real kernel semantics, so
timing includes congestion control, head-of-line blocking, and topology effects. Those are
precisely the things that move a timing-correlation result.

The two are complementary:

| | `gyre-sim` | Shadow |
|---|---|---|
| Protocol code | real | real |
| Network stack | modelled (latency + jitter) | real TCP/UDP over a simulated topology |
| Runs on | any platform, seconds | Linux only, minutes to hours |
| Scale | thousands of flows | hundreds to thousands of hosts |
| Status | **measured** | **not yet run** |

## What is needed before this can run

1. **A Linux host** (Shadow supports recent Ubuntu/Debian/Fedora), plus Shadow itself:
   see the [installation guide](https://shadow.github.io/docs/guide/install_shadow.html).
2. **Real Gyre binaries that speak the network.** The current `gyre-node` demo spins up an
   in-process testnet; Shadow needs separate client and relay binaries that bind sockets
   and take their peers from config/argv. That is the actual work item — it is a change to
   the crates, not to this directory.
3. **A topology file.** Shadow ships generators for realistic latency/bandwidth graphs;
   `network.gml` here is a deliberately tiny placeholder.

## Files

- `shadow.yaml` — a minimal experiment: a few relays and clients on a simple topology.
- `network.gml` — a placeholder topology graph.

Both are shaped to be obviously incomplete rather than plausibly finished, so nobody
mistakes them for a validated configuration.

## Running it, once the prerequisites exist

```bash
# on Linux, with shadow installed and the gyre binaries built
cargo build --release
shadow sim/shadow/shadow.yaml
```

Results should then be written up in `docs/SIMULATION.md` **as a separate section**,
clearly distinguished from the `gyre-sim` numbers — different harness, different
assumptions, different limits.
