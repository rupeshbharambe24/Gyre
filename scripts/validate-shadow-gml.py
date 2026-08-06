#!/usr/bin/env python3
"""Validate a Shadow network graph the way *Shadow* will, not the way networkx will.

Shadow's GML parser is stricter than networkx's: it rejects `#` comments outright (that
cost a CI round-trip) and only understands a small set of attributes. networkx happily
accepts both, so passing `nx.read_gml` proves very little. This checks the dialect.

    python3 scripts/validate-shadow-gml.py sim/shadow/network.gml
"""
import re
import sys

NODE_ATTRS = {"id", "host_bandwidth_up", "host_bandwidth_down"}
EDGE_ATTRS = {"source", "target", "latency", "packet_loss"}
GRAPH_ATTRS = {"directed"}


def fail(msg: str) -> None:
    print(f"INVALID: {msg}")
    sys.exit(1)


def main(path: str) -> None:
    text = open(path).read()

    # Shadow's parser dies on the first `#`. networkx does not — hence this check.
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            fail(f"line {n}: Shadow's GML parser rejects '#' comments. Put prose in the README.")

    if not re.match(r"\s*graph\s*\[", text):
        fail("must start with 'graph ['")

    depth, blocks, seen_nodes, edges = 0, [], set(), []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line in ("node [", "edge ["):
            blocks.append(line.split()[0]); depth += 1; continue
        if line == "]":
            if blocks: blocks.pop()
            depth -= 1; continue
        if line.startswith("graph ["):
            depth += 1; continue
        key = line.split()[0]
        ctx = blocks[-1] if blocks else "graph"
        allowed = {"node": NODE_ATTRS, "edge": EDGE_ATTRS, "graph": GRAPH_ATTRS}[ctx]
        if key not in allowed:
            fail(f"line {n}: '{key}' is not an attribute Shadow understands in a {ctx} "
                 f"(allowed: {sorted(allowed)})")
        if ctx == "node" and key == "id":
            seen_nodes.add(line.split()[1])
        if ctx == "edge" and key in ("source", "target"):
            edges.append((n, line.split()[1]))

    if depth != 0:
        fail("unbalanced brackets")
    if not seen_nodes:
        fail("no nodes defined")
    for n, ref in edges:
        if ref not in seen_nodes:
            fail(f"line {n}: edge references node {ref}, which is not defined")

    # Structural sanity via networkx, if available.
    try:
        import networkx as nx
        # `label=None` keys nodes by `id`. networkx's DEFAULT insists on a `label`
        # attribute, which Shadow does not want — another place the two dialects diverge,
        # and why the checks above are the primary ones.
        g = nx.read_gml(path, label=None)
        extra = f", networkx: {g.number_of_nodes()} nodes / {g.number_of_edges()} edges"
    except ImportError:
        extra = " (networkx not installed; skipped structural check)"

    print(f"VALID: {len(seen_nodes)} node(s), {len(edges)//2} edge(s){extra}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sim/shadow/network.gml")
