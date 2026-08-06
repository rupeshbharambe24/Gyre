# Shadow simulation scaffolding

> [!NOTE]
> **This runs green.** See [`docs/SIMULATION.md`](../../docs/SIMULATION.md) for results:
> 40/40 delivered end to end over simulated TCP, with **4 intra-client inversions** proving
> mixing genuinely reorders — and the honest caveat that the naive metric would have
> reported 17.
>
> Shadow is **Linux-only**, and you do not need a Linux machine to run it: the
> [workflow](../../.github/workflows/shadow.yml) uses GitHub's free runners. Trigger
> **Shadow simulation** from the Actions tab. WSL**2** also works locally (WSL1 does not —
> it translates syscalls rather than running a kernel, and Shadow's interception needs the
> real thing).

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
| Status | **measured** | **measured** |

## What is needed before this can run

1. ~~Real Gyre binaries that speak the network.~~ **Done** — `gyre-relay`, `gyre-client`
   and `gyre-sink` are real processes that bind sockets and take their peers from argv.
   Verified working outside Shadow with `./scripts/testnet.sh`, where mixing visibly
   reorders packets across processes.
2. **A Linux host with Shadow installed** — or just use the GitHub Actions workflow above.
   Two traps, both hit on the first attempt:
   - `apt install shadow` installs an unrelated package (the shadow password suite).
     Shadow the simulator ships **no prebuilt binaries** and must be built from source.
   - **The network graph must be in Shadow's GML dialect**, which is stricter than
     networkx's: no `#` comments (they fail at line 1), and only `id` /
     `host_bandwidth_up` / `host_bandwidth_down` on nodes and `source` / `target` /
     `latency` / `packet_loss` on edges. Run
     `python3 scripts/validate-shadow-gml.py sim/shadow/network.gml` before pushing —
     that check exists because this cost a CI round-trip. Explanatory prose belongs here,
     not in the `.gml`.
   - The config schema bites too: `network.graph.file` is a **struct**
     (`file: {path: ...}`), not a string; long-running servers need
     `expected_final_state: running` or Shadow reports a still-running process as a failed
     simulation; and a managed process's working directory is
     `shadow.data/hosts/<hostname>/`, not the config directory.
   - Its build dependencies must come from
     [Shadow's own install guide](https://github.com/shadow/shadow/blob/main/docs/install_dependencies.md),
     not from memory. A list missing `libglib2.0-dev` fails at cmake with
     `Package 'glib-2.0' ... not found`.
3. **A realistic topology.** `network.gml` is two regions with a slow link between them —
   enough to exercise real TCP over non-trivial latency, *not* a model of the internet.
   Replace it with a generated topology before drawing any conclusion about scale.

## Files

- `shadow.yaml` — a minimal experiment: a few relays and clients on a simple topology.
- `network.gml` — a placeholder topology graph.

Both are shaped to be obviously incomplete rather than plausibly finished, so nobody
mistakes them for a validated configuration.

## Running it, once the prerequisites exist

```bash
cargo build --release -p gyre-cli
# shadow.yaml names binaries by bare basename; Shadow resolves them through PATH.
export PATH="$PWD/target/release:$PATH"
cd sim/shadow && shadow shadow.yaml

# what each simulated host printed
find shadow.data -name '*.stdout' -exec cat {} \;
```

A successful run shows the sink reporting end-to-end delivery, and each relay logging a
*different* per-packet mixing delay — the same reordering the local testnet shows, but now
over simulated TCP with real congestion and loss.

Results should then be written up in `docs/SIMULATION.md` **as a separate section**,
clearly distinguished from the `gyre-sim` numbers — different harness, different
assumptions, different limits.
