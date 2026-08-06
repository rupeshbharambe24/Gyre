#!/usr/bin/env python3
"""Decide whether per-hop mixing actually REORDERED packets, from a Shadow sink log.

The naive check — "did the 40 payloads arrive out of order?" — proves nothing when several
clients are running: independent clients drift apart, and that produces inversions all by
itself. The only sound evidence of mixing is a packet arriving out of order relative to a
packet **the same client sent earlier**, because within one client the send order is known.

Usage:  analyse-shadow-mixing.py <sink stdout file>
Payloads must be tagged `<client>:<seq>` (gyre-client --tag).
"""
import re
import sys
from collections import defaultdict


def main(path: str) -> None:
    arrivals = []  # (client, seq) in arrival order
    for line in open(path):
        m = re.search(r'delivered #\d+ after [\d.]+s: "([^:"]+):(\d+)"', line)
        if m:
            arrivals.append((m.group(1), int(m.group(2))))

    if not arrivals:
        print("NO TAGGED PAYLOADS FOUND — was gyre-client given --tag?")
        sys.exit(1)

    per_client = defaultdict(list)
    for client, seq in arrivals:
        per_client[client].append(seq)

    total_intra = 0
    print(f"{len(arrivals)} payloads from {len(per_client)} client(s)\n")
    for client in sorted(per_client):
        order = per_client[client]
        inv = [(a, b) for i, a in enumerate(order) for b in order[i + 1:] if a > b]
        total_intra += len(inv)
        state = "REORDERED" if inv else "in order"
        print(f"  {client}: arrival order {order}  -> {state}"
              + (f" ({len(inv)} inversion(s), e.g. {inv[0][0]} before {inv[0][1]})" if inv else ""))

    # Cross-client inversions, for contrast — these prove nothing on their own.
    flat = [s for _, s in arrivals]
    cross = sum(1 for i, a in enumerate(flat) for b in flat[i + 1:] if a > b)

    print()
    print(f"intra-client inversions (EVIDENCE OF MIXING): {total_intra}")
    print(f"raw inversions across all clients (proves nothing on its own): {cross}")
    print()
    if total_intra:
        print("VERDICT: mixing measurably reordered packets within a single client's own")
        print("         stream, over simulated TCP. That cannot be explained by clients")
        print("         drifting apart.")
    else:
        print("VERDICT: NO intra-client reordering. Every client's packets arrived in the")
        print("         order it sent them, so the per-hop delays did not exceed the gaps")
        print("         between that client's own sends. The raw inversion count above is")
        print("         just independent clients interleaving — it is NOT mixing.")


if __name__ == "__main__":
    main(sys.argv[1])
