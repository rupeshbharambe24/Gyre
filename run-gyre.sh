#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Gyre — one-click local launcher (macOS / Linux)                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# Builds Gyre, starts the guarded "Shield" relay + a hidden origin on your machine,
# opens the live dashboard in your browser, and shows you how to use it.
#
#   • macOS : double-click  run-gyre.command   (or run ./run-gyre.sh)
#   • Linux : ./run-gyre.sh   (or your file manager's "Run in Terminal")
#
# This runs Gyre LOCALLY so you can see and use it. To make it reachable from the
# internet, follow docs/DEPLOY.md. Press Ctrl+C to stop.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RELAY="127.0.0.1:9500"
DASH="127.0.0.1:9600"
COOKIE="gyre-local-demo"
BIN="target/release"

printf '\n\033[1;36m  GYRE — local launcher\033[0m\n\n'

# 1) Rust toolchain -----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  echo "  Rust/cargo is not installed. It's free and takes one command:"
  echo "      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "  (or see https://rustup.rs). Then re-run this launcher."
  read -r -p "  Press Enter to close… " _ || true
  exit 1
fi

# 2) Build --------------------------------------------------------------------
echo "  Building Gyre (the first build takes a few minutes; later runs are instant)…"
if ! cargo build --release -p gyre-cli; then
  echo "  Build failed — see the errors above."
  read -r -p "  Press Enter to close… " _ || true
  exit 1
fi

# 3) Start the guarded relay (admission gate) + live dashboard ---------------
"$BIN/gyre-rendezvous" --listen "$RELAY" --dashboard "$DASH" --capacity 256 --stats-secs 15 &
RZV=$!
sleep 1

# 4) Park a hidden origin behind it so there's a live service to reach --------
"$BIN/gyre-origin" --rendezvous "$RELAY" --cookie "$COOKIE" --reply "hello from your hidden origin" &
ORIGIN=$!
sleep 1

cleanup() { kill "$RZV" "$ORIGIN" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 5) Open the dashboard -------------------------------------------------------
URL="http://$DASH/"
if   command -v open     >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 || true
elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
fi

cat <<EOF

  ✓ Gyre is LIVE on your machine.
      Dashboard : $URL   (open it in your browser)
      Relay     : $RELAY   — guarded, proof-of-work admission
      A hidden origin is parked behind cookie "$COOKIE" (it published no inbound address)

  Open another terminal and try it:
      # reach the hidden origin (solves the puzzle, gets through):
      $BIN/gyre-reach --rendezvous $RELAY --cookie "$COOKIE" --message "hello"

      # simulate a flood (skips the puzzle — all refused). Watch the dashboard:
      $BIN/gyre-reach --rendezvous $RELAY --flood 200

  Make it reachable from the internet: see docs/DEPLOY.md
  Press Ctrl+C here to stop Gyre.

EOF

wait "$RZV"
