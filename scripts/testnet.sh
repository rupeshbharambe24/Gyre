#!/usr/bin/env bash
# Launch a local Gyre testnet of real processes and push traffic through it.
#
#   ./scripts/testnet.sh [packets] [lane]
#
# Unlike the in-process demos, every relay here is a separate OS process talking over real
# sockets — which is what makes the result meaningful, and what a network simulator needs.
set -euo pipefail

PACKETS="${1:-5}"
LANE="${2:-mix}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release"
LOGS="$(mktemp -d)"
RELAYS="--relay r1=127.0.0.1:19001 --relay r2=127.0.0.1:19002 --relay r3=127.0.0.1:19003 --relay dest=127.0.0.1:19100"

cleanup() { pkill -f 'gyre-relay --label' 2>/dev/null || true; pkill -f 'gyre-sink' 2>/dev/null || true; }
trap cleanup EXIT

echo "building..."
cargo build --release -p gyre-cli >/dev/null

"$BIN/gyre-sink" --listen 127.0.0.1:19100 --expect "$PACKETS" > "$LOGS/sink.log" 2>&1 &
for i in 1 2 3; do
  "$BIN/gyre-relay" --label "r$i" --listen "127.0.0.1:1900$i" $RELAYS > "$LOGS/r$i.log" 2>&1 &
done
sleep 1

echo "=== client: $PACKETS packets on the $LANE lane, r1 -> r2 -> r3 -> dest ==="
"$BIN/gyre-client" --route r1,r2,r3 --dest dest --lane "$LANE" --packets "$PACKETS" $RELAYS

# Mixing deliberately delays packets, so give the slowest one time to arrive.
sleep 5

echo
echo "=== end-to-end delivery ==="
cat "$LOGS/sink.log"
echo
echo "=== what each relay learned (only its own neighbour) ==="
for i in 1 2 3; do echo "--- r$i ---"; tail -n +2 "$LOGS/r$i.log"; done

DELIVERED=$(grep -c 'delivered #' "$LOGS/sink.log" || true)
echo
if [ "$DELIVERED" -eq "$PACKETS" ]; then
  echo "OK: $DELIVERED/$PACKETS delivered end to end"
else
  echo "FAIL: only $DELIVERED/$PACKETS delivered"
  exit 1
fi
