# Assets

`demo.gif` — the Shield demo shown in the README — is **checked in** (it's small, ~42 KB).

Three ways to regenerate it:

```bash
# A) No terminal recorder needed — Python + ffmpeg (what produced the committed GIF):
python3 scripts/make-demo-gif.py            # -> docs/assets/demo.gif

# B) A real terminal recording with VHS (github.com/charmbracelet/vhs):
cargo build --release -p gyre-cli
vhs scripts/demo.tape

# C) asciinema (no VHS):
asciinema rec demo.cast -c "PAUSE=0.8 ./scripts/demo.sh"
agg demo.cast docs/assets/demo.gif          # github.com/asciinema/agg
```
