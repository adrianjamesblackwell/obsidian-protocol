#!/usr/bin/env python3
"""
blackwell-core/evidence-graph/evidence_graph.py

BLACKWELL EVIDENCE GRAPH (BEG) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
WHAT PROBLEM THIS SOLVES
----------------------------------------------------------------------
Every security product emits *facts*: an alert fired, a log line
matched, a hash appeared in a feed. None of them emit a *reasoned
position* on what those facts mean together. The analyst is left to
reconstruct, by hand, which facts support which conclusion, and how
strongly.

The Blackwell Evidence Graph is the data structure that makes that
reconstruction a first-class, queryable object instead of something
that lives only in an analyst's head or a free-text incident note.

----------------------------------------------------------------------
CORE ABSTRACTION
----------------------------------------------------------------------
A BEG is a typed, directed, attributed multigraph G = (V, E) where:

  V = EvidenceNode  — an atomic, sourced observation
        node.kind ∈ {RAW_EVENT, INDICATOR, ASSERTION, CONCLUSION}
        node.weight ∈ [0,1]   — intrinsic reliability of the node itself
        node.provenance       — where this fact came from (telemetry
                                  source, feed, derived-by-module)

  E = EvidenceEdge  — a typed relationship between two nodes
        edge.relation ∈ {SUPPORTS, CONTRADICTS, TEMPORALLY_PRECEDES,
                          CAUSES, CO_OCCURS_WITH, DERIVED_FROM}
        edge.strength ∈ [0,1] — how strongly source supports/contradicts target

This is deliberately NOT the same thing as a "knowledge graph" of
entities (host, user, IP) connected by relationships — that graph
already exists informally in every SIEM. BEG's nodes are *claims*,
not entities. The entity graph is a side-effect you can project out
of BEG (see blackwell-core/knowledge-graph), not the primary object.

----------------------------------------------------------------------
WHY A SEPARATE GRAPH FROM THE CORRELATION OUTPUT
----------------------------------------------------------------------
correlation-engine/correlate.py groups raw events into incidents.
That is necessary but is a PROJECTION, not the underlying evidence
state. Two different incidents might share a node (e.g. the same
CVE-2021-4034 detection feeding both a "privilege escalation" claim
and a "root cause: missing EDR" claim). Once you collapse to incidents
you lose that shared structure. BEG keeps it.

The relationship to the rest of OBSIDIAN PROTOCOL:

    telemetry/*           --> RAW_EVENT nodes
    threat-intel/*         --> INDICATOR nodes
    correlation-engine/*    --> ASSERTION nodes (an "incident" is an
                                  assertion: "these events form one
                                  operation")
    risk-engine, root-cause  --> ASSERTION / CONCLUSION nodes
    blackwell BCA/BRS/Decision --> consume and add to this same graph

This module owns graph construction, integrity checks, and query
primitives. It does not itself decide confidence values — that is
the Confidence Engine's job (blackwell-core/confidence-engine). BEG
is the substrate; BCA, BRS, Confidence Engine, and Decision Engine
are reasoning passes that read and write it.

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
Construction from N telemetry events + M indicators:  O(N + M)
Path query between two nodes (used by Attack Path Prediction):
    bounded BFS, O(V + E) worst case, but in practice bounded by
    `max_hops` (default 6), giving O(b^max_hops) for branching factor b
Contradiction detection (see find_contradictions): O(E) — single pass
over edges typed CONTRADICTS, no global fixpoint required because we
do not attempt automatic belief revision (see Known Limitations).

----------------------------------------------------------------------
KNOWN LIMITATIONS (stated up front, not discovered later)
----------------------------------------------------------------------
1. No automatic belief revision. If two ASSERTION nodes contradict,
   BEG flags it (find_contradictions) but does not pick a winner.
   That is a deliberate design choice — automatic contradiction
   resolution in security data is an open research problem and a
   wrong automatic answer is worse than a flagged ambiguity. The
   Decision Engine surfaces contradictions to a human rather than
   silently resolving them.
2. Edge strengths are produced by upstream modules (BCA, Confidence
   Engine) and trusted as given; BEG does not independently verify
   them. Garbage in the edges produces garbage graph queries.
3. The graph is held in memory and serialized to JSON. This is fine
   at lab/demo scale (hundreds to low thousands of nodes). It is not
   a substitute for a real graph database at SOC scale — see
   docs/research-findings.md Future Work for the Neo4j/JanusGraph
   migration path this was designed to allow.
"""

import json
import os
import hashlib
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


class NodeKind(str, Enum):
    RAW_EVENT = "RAW_EVENT"
    INDICATOR = "INDICATOR"
    ASSERTION = "ASSERTION"
    CONCLUSION = "CONCLUSION"


class EdgeRelation(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    TEMPORALLY_PRECEDES = "TEMPORALLY_PRECEDES"
    CAUSES = "CAUSES"
    CO_OCCURS_WITH = "CO_OCCURS_WITH"
    DERIVED_FROM = "DERIVED_FROM"


@dataclass
class EvidenceNode:
    node_id: str
    kind: NodeKind
    label: str
    weight: float                 # intrinsic reliability, 0..1
    provenance: str                # which module/source produced this node
    timestamp: Optional[str] = None
    attributes: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


@dataclass
class EvidenceEdge:
    edge_id: str
    source: str
    target: str
    relation: EdgeRelation
    strength: float                # 0..1, how strongly source bears on target
    rationale: str = ""
    produced_by: str = "unknown"   # which Blackwell module added this edge

    def to_dict(self):
        d = asdict(self)
        d["relation"] = self.relation.value
        return d


class EvidenceGraph:
    """
    In-memory evidence graph with adjacency indices for O(1) neighbor
    lookups in both directions. See module docstring for the formal
    model.
    """

    def __init__(self):
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: dict[str, EvidenceEdge] = {}
        self._out_adj: dict[str, list[str]] = {}
        self._in_adj: dict[str, list[str]] = {}

    # ---- construction -------------------------------------------------

    def add_node(self, kind: NodeKind, label: str, weight: float,
                 provenance: str, timestamp: str = None,
                 attributes: dict = None, node_id: str = None) -> str:
        if node_id is None:
            node_id = self._make_id("node", label, provenance, timestamp)
        node = EvidenceNode(
            node_id=node_id, kind=kind, label=label, weight=weight,
            provenance=provenance, timestamp=timestamp,
            attributes=attributes or {},
        )
        self.nodes[node_id] = node
        self._out_adj.setdefault(node_id, [])
        self._in_adj.setdefault(node_id, [])
        return node_id

    def add_edge(self, source: str, target: str, relation: EdgeRelation,
                 strength: float, rationale: str = "",
                 produced_by: str = "unknown") -> str:
        if source not in self.nodes or target not in self.nodes:
            raise ValueError(
                f"Cannot add edge: missing endpoint(s) {source} -> {target}"
            )
        edge_id = self._make_id("edge", source, target, relation.value)
        edge = EvidenceEdge(
            edge_id=edge_id, source=source, target=target,
            relation=relation, strength=strength, rationale=rationale,
            produced_by=produced_by,
        )
        self.edges[edge_id] = edge
        self._out_adj.setdefault(source, []).append(edge_id)
        self._in_adj.setdefault(target, []).append(edge_id)
        return edge_id

    @staticmethod
    def _make_id(*parts) -> str:
        raw = "|".join(str(p) for p in parts if p is not None)
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    # ---- query primitives ----------------------------------------------

    def out_edges(self, node_id: str) -> list[EvidenceEdge]:
        return [self.edges[e] for e in self._out_adj.get(node_id, [])]

    def in_edges(self, node_id: str) -> list[EvidenceEdge]:
        return [self.edges[e] for e in self._in_adj.get(node_id, [])]

    def supporting_evidence(self, node_id: str) -> list[EvidenceNode]:
        """All nodes with a SUPPORTS edge pointing at node_id."""
        return [
            self.nodes[e.source] for e in self.in_edges(node_id)
            if e.relation == EdgeRelation.SUPPORTS
        ]

    def contradicting_evidence(self, node_id: str) -> list[EvidenceNode]:
        return [
            self.nodes[e.source] for e in self.in_edges(node_id)
            if e.relation == EdgeRelation.CONTRADICTS
        ]

    def find_contradictions(self) -> list[dict]:
        """
        Single pass over CONTRADICTS edges (see module docstring,
        complexity section). Returns a flat list rather than attempting
        any resolution — surfacing ambiguity is the design choice here,
        not resolving it automatically.
        """
        out = []
        for e in self.edges.values():
            if e.relation == EdgeRelation.CONTRADICTS:
                out.append({
                    "edge_id": e.edge_id,
                    "node_a": self.nodes[e.source].label,
                    "node_b": self.nodes[e.target].label,
                    "strength": e.strength,
                    "rationale": e.rationale,
                })
        return out

    def bounded_path(self, start: str, end: str, max_hops: int = 6) -> Optional[list[str]]:
        """
        BFS bounded by max_hops. Used by attack-path-prediction to ask
        "is there a plausible evidentiary path from this initial
        access node to this impact node, and if so, how many
        inferential hops does it take." Returns a node_id path or None.
        """
        if start not in self.nodes or end not in self.nodes:
            return None
        from collections import deque
        frontier = deque([(start, [start])])
        visited = {start}
        while frontier:
            current, path = frontier.popleft()
            if current == end:
                return path
            if len(path) - 1 >= max_hops:
                continue
            for e in self.out_edges(current):
                nxt = e.target
                if nxt not in visited:
                    visited.add(nxt)
                    frontier.append((nxt, path + [nxt]))
        return None

    def subgraph_for(self, node_id: str, depth: int = 2) -> dict:
        """Returns the local neighborhood of a node up to `depth` hops,
        in both directions — this is what a UI would render when an
        analyst clicks on a single conclusion to ask "why do you believe
        this?"."""
        seen_nodes = {node_id}
        seen_edges = set()
        frontier = [node_id]
        for _ in range(depth):
            next_frontier = []
            for nid in frontier:
                for e in self.out_edges(nid) + self.in_edges(nid):
                    if e.edge_id not in seen_edges:
                        seen_edges.add(e.edge_id)
                        other = e.target if e.source == nid else e.source
                        if other not in seen_nodes:
                            seen_nodes.add(other)
                            next_frontier.append(other)
            frontier = next_frontier
        return {
            "nodes": [self.nodes[n].to_dict() for n in seen_nodes],
            "edges": [self.edges[e].to_dict() for e in seen_edges],
        }

    # ---- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
        }

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load_from_obsidian_outputs(cls) -> "EvidenceGraph":
        """
        Builds a BEG from the existing OBSIDIAN PROTOCOL module outputs:
        unified_timeline.ndjson (RAW_EVENT), threat-intel cve_intel_output.json
        (INDICATOR), correlated_incidents.json (ASSERTION). This is the
        glue between the legacy per-module pipeline and the Blackwell
        reasoning layer — every existing module keeps working standalone;
        BEG just also ingests their outputs.
        """
        g = cls()

        # RAW_EVENT nodes from telemetry
        timeline_path = os.path.join(BASE_DIR, "telemetry", "output", "unified_timeline.ndjson")
        event_node_ids = {}
        if os.path.exists(timeline_path):
            with open(timeline_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = json.loads(line)
                    nid = g.add_node(
                        kind=NodeKind.RAW_EVENT,
                        label=f"{ev.get('source','?')}: {ev.get('category','?')}",
                        weight=0.9,  # raw telemetry is trusted by default
                        provenance=f"telemetry:{ev.get('source','unknown')}",
                        timestamp=ev.get("timestamp"),
                        attributes=ev,
                        node_id=f"evt-{ev.get('event_id', g._make_id(ev))}",
                    )
                    event_node_ids[ev.get("event_id")] = nid

        # INDICATOR nodes from threat intel
        intel_path = os.path.join(BASE_DIR, "threat-intel", "cve_intel_output.json")
        if os.path.exists(intel_path):
            with open(intel_path) as f:
                intel = json.load(f)
            results = intel.get("results", {}) if isinstance(intel, dict) else {}
            # results is keyed by CVE id -> {nvd, kev, known_campaigns}
            for cve, entry in results.items():
                g.add_node(
                    kind=NodeKind.INDICATOR,
                    label=f"Indicator: {cve}",
                    weight=0.85,
                    provenance="threat-intel:nvd_kev",
                    attributes=entry,
                    node_id=f"ind-{cve}",
                )

        # ASSERTION nodes from correlation engine
        corr_path = os.path.join(BASE_DIR, "correlation-engine", "output", "correlated_incidents.json")
        if os.path.exists(corr_path):
            with open(corr_path) as f:
                incidents = json.load(f)
            for inc in incidents:
                assertion_id = f"assert-{inc['incident_id']}"
                g.add_node(
                    kind=NodeKind.ASSERTION,
                    label=f"Incident {inc['incident_id']}: {inc.get('severity','?')}",
                    weight=inc.get("confidence", 50) / 100.0,
                    provenance="correlation-engine:correlate.py",
                    timestamp=inc.get("first_seen"),
                    attributes={k: v for k, v in inc.items() if k != "raw_event_ids"},
                    node_id=assertion_id,
                )
                for eid in inc.get("raw_event_ids", []):
                    src_node = event_node_ids.get(eid, f"evt-{eid}")
                    if src_node in g.nodes:
                        g.add_edge(
                            source=src_node, target=assertion_id,
                            relation=EdgeRelation.SUPPORTS,
                            strength=inc.get("confidence", 50) / 100.0,
                            rationale="Raw event grouped into this incident by BCA",
                            produced_by="correlation-engine",
                        )
                for cve in inc.get("cve_chain", []):
                    ind_node = f"ind-{cve}"
                    if ind_node in g.nodes:
                        g.add_edge(
                            source=ind_node, target=assertion_id,
                            relation=EdgeRelation.SUPPORTS,
                            strength=0.8,
                            rationale=f"Indicator {cve} associated with this incident",
                            produced_by="evidence-graph:ingest",
                        )

        return g


def main():
    g = EvidenceGraph.load_from_obsidian_outputs()
    out_path = os.path.join(OUTPUT_DIR, "evidence_graph.json")
    g.save(out_path)

    print("=" * 70)
    print("  BLACKWELL EVIDENCE GRAPH (BEG) v1.0")
    print("=" * 70)
    print(f"\n  Nodes: {len(g.nodes)}   Edges: {len(g.edges)}")
    by_kind = {}
    for n in g.nodes.values():
        by_kind[n.kind.value] = by_kind.get(n.kind.value, 0) + 1
    for k, v in by_kind.items():
        print(f"    {k:12s}: {v}")
    contradictions = g.find_contradictions()
    print(f"\n  Contradictions flagged: {len(contradictions)}")
    print(f"\n[+] Saved: {out_path}")


if __name__ == "__main__":
    main()
