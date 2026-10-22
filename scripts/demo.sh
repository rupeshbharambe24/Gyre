#!/usr/bin/env bash
# A short, narrated demonstration of the Gyre inbound Shield, tuned for screen-recording
# (asciinema / VHS). It runs four real OS processes and shows the admission gate: a client
# that solves the puzzle reaches a hidden origin; a flood that skips it is refused.
#
#   ./scripts/demo.sh            # SHA-256 admission puzzle (default build)
#   POW=equix ./scripts/demo.sh  # memory-hard Equi-X (needs: cargo build --features equix)
#
# To produce a GIF, see scripts/demo.tape (VHS) or run:
#   asciinema rec demo.cast -c ./scripts/demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release"
PORT="${PORT:-9500}"
COOKIE="a-long-random-shared-secret"
POW="${POW:-sha256}"
FLOOD="${FLOOD:-50}"
PAUSE="${PAUSE:-1.2}"   # seconds between steps — paced for a readable recording

# Colors (fall back to plain if not a TTY).
if [ -t 1 ]; then B=$'\e[1m'; D=$'\e[2m'; G=$'\e[32m'; R=$'\e[31m'; C=$'\e[36m'; Z=$'\e[0m'
else B=; D=; G=; R=; C=; Z=; fi
step() { printf '\n%s▸ %s%s\n' "$C$B" "$1" "$Z"; sleep "$PAUSE"; }

printf '%s' "$B$C"
cat <<'BANNER'
  ┌───────────────────────────────────────────────────────────┐
  │  GYRE — the inbound Shield, live across real OS processes   │
  │  origin-hiding + a proof-of-work DoS admission gate         │
  └───────────────────────────────────────────────────────────┘
BANNER
printf '%s' "$Z"

# Build quietly if the binaries are missing (keeps the recording focused on the demo).
if [ ! -x "$BIN/gyre-rendezvous" ]; then
  printf '%s  (building release binaries, one-time…)%s\n' "$D" "$Z"
  cargo build --release -p gyre-cli >/dev/null 2>&1
fi

LOGS="$(mktemp -d)"
cleanup() { kill "${RZV_PID:-}" "${ORIGIN_PID:-}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

step "1/4  Start the guarded relay — admission gate + DoS bounds (--pow $POW)"
"$BIN/gyre-rendezvous" --listen "127.0.0.1:$PORT" --pow "$POW" --capacity 64 --max-inflight 32 \
  > "$LOGS/rzv.log" 2>&1 &
RZV_PID=$!
sleep 1
sed "s/^/   $D/; s/$/$Z/" "$LOGS/rzv.log"

step "2/4  The origin dials OUT and parks — it binds NO inbound address"
printf '   %snothing to find, nothing to flood directly%s\n' "$D" "$Z"
"$BIN/gyre-origin" --rendezvous "127.0.0.1:$PORT" --cookie "$COOKIE" --reply "hidden origin" \
  > "$LOGS/origin.log" 2>&1 &
ORIGIN_PID=$!
sleep 1

step "3/4  A legitimate client solves the puzzle and reaches the hidden origin"
printf '   %s' "$G"
"$BIN/gyre-reach" --rendezvous "127.0.0.1:$PORT" --cookie "$COOKIE" --message "ping" | sed "s/^/   /"
printf '%s' "$Z"

step "4/4  A flood of $FLOOD connections that SKIP the puzzle"
printf '   %s' "$R"
"$BIN/gyre-reach" --rendezvous "127.0.0.1:$PORT" --flood "$FLOOD" | sed "s/^/   /"
printf '%s' "$Z"
REFUSED=$(grep -c "refused" "$LOGS/rzv.log" 2>/dev/null || echo 0)
printf '   %sgate refused %s connections · parked map stayed bounded%s\n' "$D" "$REFUSED" "$Z"

sleep "$PAUSE"
printf '\n%s✔ The gate runs as a real daemon:%s pay the work → through; skip it → refused.\n' "$G$B" "$Z"
printf '  %sNo volumetric L3/L4 defence (that is a scrubber, D22). Deploy guide: docs/DEPLOY.md%s\n\n' "$D" "$Z"
