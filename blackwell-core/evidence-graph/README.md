# BLACKWELL EVIDENCE GRAPH (BEG) v1.0

### The reasoning substrate beneath every other Blackwell module

## Why this exists

Every detection product surfaces *facts*. None of them surface a
*reasoned position* on what those facts mean together, with the
supporting evidence attached and queryable. An analyst who wants to
know "why does the system believe this is a real incident" usually
has to reconstruct that by hand from logs, tickets, and memory.

BEG makes that reconstruction structural: every conclusion the
platform reaches is a node, and every piece of evidence behind it is
an edge with a strength and a rationale. "Why do you believe this?"
becomes a graph query (`subgraph_for`), not an investigation.

## Formal model

A BEG is a typed, directed, attributed multigraph `G = (V, E)`.

**Nodes** (`EvidenceNode`) — one of four kinds:

| Kind | Meaning | Produced by |
|---|---|---|
| `RAW_EVENT` | An atomic telemetry observation | `telemetry/` |
| `INDICATOR` | An external threat-intel fact (CVE, IOC) | `threat-intel/`, `ioc-decay/` |
| `ASSERTION` | A claim derived from other nodes ("these 6 events are one operation") | `correlation-engine/` (BCA), `root-cause/` |
| `CONCLUSION` | A claim the platform is prepared to act on | `decision-engine/` |

Each node carries an intrinsic `weight ∈ [0,1]` (how reliable is this
node on its own, independent of corroboration) and `provenance`
(which module/source produced it).

**Edges** (`EvidenceEdge`) — one of six relations:

`SUPPORTS`, `CONTRADICTS`, `TEMPORALLY_PRECEDES`, `CAUSES`,
`CO_OCCURS_WITH`, `DERIVED_FROM` — each with a `strength ∈ [0,1]` and
a free-text `rationale`.

## What this is *not*

BEG is not an entity graph (host ↔ user ↔ IP). That graph is useful
but already exists informally in every SIEM, and conflating it with
the evidence graph is a common design mistake: entities don't have
confidence levels, claims do. The entity-relationship view is a
projection you can derive *from* BEG (see
[`blackwell-core/knowledge-graph`](../knowledge-graph/README.md)) — it
is not the primary structure.

## Query primitives

- `supporting_evidence(node)` / `contradicting_evidence(node)` — direct
  neighbors by relation type.
- `find_contradictions()` — single pass over `CONTRADICTS` edges.
  **Deliberately does not resolve them.** Automatic contradiction
  resolution in security evidence is an open problem; a confidently
  wrong automatic answer is worse than a flagged ambiguity surfaced to
  a human. This is a design choice, not a missing feature.
- `bounded_path(start, end, max_hops)` — BFS bounded by `max_hops`
  (default 6). Used by Attack Path Prediction to ask "is there a
  plausible evidentiary chain from this initial-access node to this
  impact node, and how many inferential hops does it take."
- `subgraph_for(node, depth)` — local neighborhood extraction. This is
  the "why do you believe this" operation a UI would call when an
  analyst clicks a conclusion.

## Complexity

| Operation | Complexity |
|---|---|
| Construction from N events + M indicators | O(N + M) |
| `bounded_path` | O(b^max_hops), b = branching factor, bounded by max_hops=6 default |
| `find_contradictions` | O(E), single pass |
| `subgraph_for(depth=d)` | O(b^d) |

## Relationship to the rest of OBSIDIAN PROTOCOL

`load_from_obsidian_outputs()` ingests the *existing* module outputs
(`telemetry/output/unified_timeline.ndjson`,
`threat-intel/cve_intel_output.json`,
`correlation-engine/output/correlated_incidents.json`) and turns them
into BEG nodes and edges. Every legacy module keeps working completely
standalone — BEG is an additional consumer of their output, not a
replacement. This is the design principle for the whole Blackwell
layer: it sits *on top of* the existing 17-module pipeline, it does
not fork it.

## Usage

```bash
# Run after the standard OBSIDIAN PROTOCOL pipeline has produced
# telemetry, threat-intel, and correlation output:
python3 blackwell-core/evidence-graph/evidence_graph.py
```

Output: `blackwell-core/evidence-graph/output/evidence_graph.json`

This file is the shared input for BCA, BRS, the Confidence Engine,
and the Decision Engine — see
[`blackwell-core/README.md`](../README.md) for the full pipeline
order.

## Known limitations

1. **No automatic belief revision.** Contradictions are flagged, not
   resolved. See "Query primitives" above.
2. **Edge strengths are trusted as given.** BEG does not independently
   verify the strengths that upstream modules assign; it is a
   substrate, not a validator. Validation of those strengths is what
   [`blackwell-core/benchmark`](../benchmark/README.md) is for.
3. **In-memory + JSON serialization.** Fine at lab scale (hundreds to
   low thousands of nodes). Not a substitute for a real graph database
   at SOC scale. The node/edge schema was deliberately kept
   property-graph-shaped (typed nodes, typed attributed edges) so a
   migration to Neo4j or JanusGraph is a storage-layer swap, not a
   model rewrite — see `docs/research-findings.md` Future Work.
