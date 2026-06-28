# RISK GRAPH
### OBSIDIAN PROTOCOL / Attack Path Visualization

## Problem

Risk reports are usually flat tables ("CVE-X: High"). For management
and architects, the most critical question is often not a table
question at all — it's a **path** question: "how does an attacker
actually get from the internet to the database?"

## Solution

`risk_graph.py` produces the real attack chain (VECTOR-I → VECTOR-II,
with real scores from the Risk Engine) plus a plausible extension
scenario (credential dump → lateral movement → database) as a single
directed acyclic graph (DAG).

## Real vs. Hypothetical Distinction (Critical)

Nodes in the graph fall into two types:

- **Real (confirmed=True):** the `internet → target49 → shell → root`
  chain — this was **actually exploited** in the lab, with evidence in
  `docs/walkthrough.md`.
- **Hypothetical (confirmed=False):** `root → creddump → lateral →
  database` — this segment was **never exploited**; it is only a
  projection of "what the chain would look like if it continued from
  here."

This distinction is also encoded visually in the Mermaid output: real
steps use a solid line and a darker color, hypothetical steps use a
dashed line and a grey/muted color. Hiding this distinction is one of
the most dangerous mistakes a report can make — conflating "possible"
with "proven."

## Usage

```bash
python3 risk-graph/risk_graph.py
```

Output: `docs/risk-graph.mermaid` (renders automatically on GitHub),
`risk-graph/output/risk_graph.json` (raw node/edge list — importable
into tools like Neo4j or Gephi).

## Known Limitation

The graph is currently static/hand-defined (the `build_graph()`
function constructs a fixed chain). In a real production system, this
would be built **dynamically** from the Correlation Engine's
`correlated_incidents.json` output — each incident becoming an edge,
each actor/entity becoming a node. This project keeps it deliberately
simple/static because the goal here is to demonstrate the methodology.
