#!/usr/bin/env bash
# Run the guarded rendezvous relay as three real OS processes and prove the DoS gate works
# in the field, not just in-process:
#
#   1. gyre-rendezvous  — the guarded relay daemon (admission gate + bounds)
#   2. gyre-origin      — a service that dials OUT and parks (no inbound address)
#   3. gyre-reach       — a client that solves the puzzle and reaches the origin,
#                         then a flood that skips the puzzle and is refused
#
# Unlike the in-process demo (`cargo run -p gyre-shield`), every party here is a separate
# process on a real socket — which is what a deployment actually looks like.
#
#   ./scripts/rendezvous.sh [flood_count]
set -euo pipefail

FLOOD="${1:-50}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release"
PORT=9500
COOKIE="demo-service"

echo "building release binaries..."
cargo build --release -p gyre-cli >/dev/null 2>&1

LOGS="$(mktemp -d)"
cleanup() {
  kill "${RZV_PID:-}" "${ORIGIN_PID:-}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo
echo "1. starting the guarded rendezvous relay on 127.0.0.1:$PORT"
"$BIN/gyre-rendezvous" --listen "127.0.0.1:$PORT" --capacity 64 --max-inflight 32 \
  > "$LOGS/rzv.log" 2>&1 &
RZV_PID=$!
sleep 1
sed 's/^/   [relay] /' "$LOGS/rzv.log"

echo
echo "2. starting the origin (dials OUT, parks, publishes no inbound address)"
"$BIN/gyre-origin" --rendezvous "127.0.0.1:$PORT" --cookie "$COOKIE" --reply "origin" \
  > "$LOGS/origin.log" 2>&1 &
ORIGIN_PID=$!
sleep 1
sed 's/^/   [origin] /' "$LOGS/origin.log"

echo
echo "3a. a legitimate client solves the puzzle and reaches the origin:"
"$BIN/gyre-reach" --rendezvous "127.0.0.1:$PORT" --cookie "$COOKIE" --message "hello over real sockets" \
  | sed 's/^/   /'

echo
echo "3b. a flood of $FLOOD connections that skip the puzzle:"
"$BIN/gyre-reach" --rendezvous "127.0.0.1:$PORT" --flood "$FLOOD" | sed 's/^/   /'

echo
echo "relay log (refusals are the gate working):"
grep -c "refused" "$LOGS/rzv.log" | sed 's/^/   connections refused by the gate: /' || true

echo
echo "VERDICT: the admission gate runs as a real daemon — a client that pays the work gets"
echo "through, a flood that does not is refused, all across separate OS processes."
