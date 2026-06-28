#!/usr/bin/env python3
"""
blackwell-core/knowledge-graph/knowledge_graph.py

BLACKWELL KNOWLEDGE GRAPH (BKG) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM AND POSITIONING
----------------------------------------------------------------------
evidence-graph/README.md is explicit that BEG's nodes are claims, not
entities, and that an entity-relationship view is a *projection* you
derive from BEG rather than a separate primary structure. This module
is that projection.

BKG answers a different question than BEG. BEG answers "what evidence
supports this conclusion, and how strongly." BKG answers "what is this
host's/user's/CVE's relationship to everything else we know" — the
classic security knowledge-graph question (entity-centric, not
claim-centric), but derived mechanically from BEG rather than
maintained as a second, independently-updated source of truth. This
matters: if BKG were maintained separately, it could drift out of
sync with the evidence that justifies it. By deriving it as a
projection, BKG is always exactly as current as the Evidence Graph it
was built from, and recomputing it is a pure function, not a sync
problem.

----------------------------------------------------------------------
PROJECTION RULE
----------------------------------------------------------------------
For every EvidenceNode n, BKG extracts zero or more ENTITIES from
n.attributes using a fixed extraction schema per node kind:

    RAW_EVENT    -> {host, user, src_ip} entities (if present)
    INDICATOR    -> {cve} entity, plus {vendor_project} if present
    ASSERTION    -> {actor_key} entity (parsed into its underlying
                     host/user/ip), plus each {cve} in cve_chain
    CONCLUSION   -> entities referenced in attributes, e.g. {cve}
                     for a BRS conclusion

For every pair of entities that co-occur as extractions from the SAME
evidence node, BKG adds a RELATED_TO entity-edge, annotated with:
    - the evidence node_id(s) that licensed the relationship
    - a derived strength = mean(evidence_node.weight for licensing nodes)

This means every edge in BKG is directly traceable back to the BEG
node(s) that justify it — "why does the graph think this host is
related to this CVE" resolves to "because RAW_EVENT node X, weight
0.9, mentioned both."

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
Entity extraction: O(V) — one pass over BEG nodes.
Edge construction: O(V * k^2) where k = max entities extracted per
single node (small and bounded — at most host+user+src_ip+cve, so
k <= 4 in this schema). Effectively linear in practice.

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. No entity resolution / aliasing. "user:1000" and a hypothetical
   "user:root" referring to the same underlying account post-privilege-
   escalation are treated as two distinct entities, not merged. This
   is the same limitation BCA documents (Known Limitations #1) at the
   correlation level, inherited here at the entity level. A real
   identity-resolution layer is future work.
2. Extraction schema is fixed and hand-coded per node kind. Adding a
   new telemetry source with a different attribute shape requires a
   schema update here, not automatic discovery.
3. RELATED_TO is a single, undifferentiated relationship type. A
   richer schema (HOSTED_ON, EXPLOITED_BY, COMMUNICATES_WITH) is
   possible future work once there are enough distinct relationship
   kinds in the underlying evidence to justify it — this project's
   current lab data does not yet exercise enough relationship variety
   to make a richer typed schema meaningfully different from
   RELATED_TO in practice, and we did not want to add unused
   complexity to satisfy an aesthetic of completeness.
"""

import json
import os
import sys
from dataclasses import dataclass, asdict, field
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind  # noqa: E402

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


@dataclass
class Entity:
    entity_id: str
    entity_type: str  # host | user | ip | cve | vendor
    label: str


@dataclass
class EntityEdge:
    source: str
    target: str
    relation: str = "RELATED_TO"
    strength: float = 0.0
    licensing_nodes: list = field(default_factory=list)


def extract_entities(node) -> list[Entity]:
    out = []
    attrs = node.attributes or {}

    if node.kind == NodeKind.RAW_EVENT:
        if attrs.get("host"):
            out.append(Entity(f"host:{attrs['host']}", "host", attrs["host"]))
        if attrs.get("user"):
            out.append(Entity(f"user:{attrs['user']}", "user", attrs["user"]))
        extra = attrs.get("extra", {})
        if extra.get("src_ip"):
            out.append(Entity(f"ip:{extra['src_ip']}", "ip", extra["src_ip"]))
        if attrs.get("cve"):
            out.append(Entity(f"cve:{attrs['cve']}", "cve", attrs["cve"]))

    elif node.kind == NodeKind.INDICATOR:
        cve = attrs.get("nvd", {}).get("cve_id") or node.node_id.replace("ind-", "")
        out.append(Entity(f"cve:{cve}", "cve", cve))
        vendor = attrs.get("kev", {}).get("vendor_project")
        if vendor:
            out.append(Entity(f"vendor:{vendor}", "vendor", vendor))

    elif node.kind == NodeKind.ASSERTION:
        actor = attrs.get("actor_key")
        if actor and ":" in actor:
            etype, val = actor.split(":", 1)
            etype = {"ip": "ip", "user": "user", "host": "host"}.get(etype, "actor")
            out.append(Entity(f"{etype}:{val}", etype, val))
        for cve in attrs.get("cve_chain", []) or []:
            out.append(Entity(f"cve:{cve}", "cve", cve))

    elif node.kind == NodeKind.CONCLUSION:
        cve = attrs.get("cve")
        if cve:
            out.append(Entity(f"cve:{cve}", "cve", cve))

    return out


def build_knowledge_graph(graph: EvidenceGraph) -> tuple[dict, list[EntityEdge]]:
    entities: dict[str, Entity] = {}
    edge_accumulator: dict[tuple, list] = {}

    for node in graph.nodes.values():
        node_entities = extract_entities(node)
        for e in node_entities:
            entities[e.entity_id] = e
        for e1, e2 in combinations(node_entities, 2):
            key = tuple(sorted([e1.entity_id, e2.entity_id]))
            edge_accumulator.setdefault(key, []).append((node.node_id, node.weight))

    edges = []
    for (a, b), licensors in edge_accumulator.items():
        strength = sum(w for _, w in licensors) / len(licensors)
        edges.append(EntityEdge(
            source=a, target=b, strength=round(strength, 3),
            licensing_nodes=[nid for nid, _ in licensors],
        ))

    return entities, edges


def main():
    graph = EvidenceGraph.load_from_obsidian_outputs()
    if not graph.nodes:
        print("[!] Evidence Graph is empty. Run the OBSIDIAN PROTOCOL pipeline first.")
        sys.exit(1)

    entities, edges = build_knowledge_graph(graph)

    print("=" * 70)
    print("  BLACKWELL KNOWLEDGE GRAPH (BKG) v1.0")
    print("=" * 70)
    print(f"\n  Entities: {len(entities)}   Relationships: {len(edges)}\n")
    by_type = {}
    for e in entities.values():
        by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
    for t, c in by_type.items():
        print(f"    {t:10s}: {c}")

    print("\n  --- TOP RELATIONSHIPS (by strength) ---\n")
    for edge in sorted(edges, key=lambda x: -x.strength)[:10]:
        a_label = entities[edge.source].label
        b_label = entities[edge.target].label
        print(f"  {a_label}  <-->  {b_label}   strength={edge.strength}  "
              f"(licensed by {len(edge.licensing_nodes)} evidence node(s))")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "knowledge_graph.json")
    with open(out_path, "w") as f:
        json.dump({
            "entities": [asdict(e) for e in entities.values()],
            "edges": [asdict(e) for e in edges],
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Saved: {out_path}")


if __name__ == "__main__":
    main()
