# Shadow simulation scaffolding

> [!CAUTION]
> **This has not been run yet — no Shadow results exist.** Shadow is **Linux-only** (it
> intercepts syscalls) and the development machine runs macOS. The config below is now
> complete and points at binaries that really exist, but until the workflow goes green
> there are no numbers here to cite.
>
> **You do not need to own a Linux machine to run it.** Two free options:
> 1. **GitHub Actions** — `.github/workflows/shadow.yml` builds Shadow and runs this
>    experiment. Public repositories get unlimited free Linux runners, so this costs
>    nothing and is reproducible for anyone. Trigger it from the Actions tab.
> 2. **WSL2 on Windows** — a real Linux kernel, so Shadow should work. WSL**1** will not:
>    it translates syscalls rather than running a kernel, and Shadow's interception needs
>    the real thing. Check with `wsl -l -v` and upgrade with `wsl --set-version <distro> 2`.

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

1. ~~Real Gyre binaries that speak the network.~~ **Done** — `gyre-relay`, `gyre-client`
   and `gyre-sink` are real processes that bind sockets and take their peers from argv.
   Verified working outside Shadow with `./scripts/testnet.sh`, where mixing visibly
   reorders packets across processes.
2. **A Linux host with Shadow installed** — or just use the GitHub Actions workflow above.
   Two traps, both hit on the first attempt:
   - `apt install shadow` installs an unrelated package (the shadow password suite).
     Shadow the simulator ships **no prebuilt binaries** and must be built from source.
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
