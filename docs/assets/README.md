# Assets

`demo.gif` — the README demo — is **generated**, not checked in by default (keeps the repo light).

Produce it from the repo root:

```bash
cargo build --release -p gyre-cli   # build once
vhs scripts/demo.tape               # writes demo.gif here (needs https://github.com/charmbracelet/vhs)
```

Or with asciinema (no VHS):

```bash
asciinema rec demo.cast -c "PAUSE=0.8 ./scripts/demo.sh"
agg demo.cast docs/assets/demo.gif   # github.com/asciinema/agg
```

Then commit `docs/assets/demo.gif` so it renders in the README.
