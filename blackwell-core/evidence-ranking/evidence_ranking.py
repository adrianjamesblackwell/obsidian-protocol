#!/usr/bin/env python3
"""
blackwell-core/evidence-ranking/evidence_ranking.py

BLACKWELL EVIDENCE RANKING (BER) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
An Evidence Graph with hundreds or thousands of nodes is not, by
itself, something an analyst can triage. Confidence (BCE) tells you
how much to believe a given conclusion. It does not tell you WHICH
conclusion to look at first when you have limited analyst time — those
are different questions. A low-confidence conclusion attached to a
CRITICAL-severity, actively-exploited CVE may deserve attention before
a high-confidence conclusion about a LOW-severity finding.

BER answers "what should an analyst look at first," as a distinct
ranking problem from "how much should the system believe this."

----------------------------------------------------------------------
FORMAL MODEL
----------------------------------------------------------------------
For each CONCLUSION or ASSERTION node a, BER computes a priority
score:

    priority(a) = w_s * severity_weight(a)
                + w_c * (1 - confidence(a))     <- INVERTED, see below
                + w_r * recency(a)
                + w_b * blast_radius(a)

    w = (w_s=0.35, w_b=0.25, w_r=0.20, w_c=0.20)

SEVERITY_WEIGHT(a):
    CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.15
    (read directly from the node's severity attribute, set upstream
    by BCA/BRS — BER does not re-derive severity, it consumes it)

CONFIDENCE TERM — WHY INVERTED:
    This is the part of BER that is easy to get backwards. We rank
    LOWER-confidence findings HIGHER for analyst attention, not lower
    — given equal severity. The reasoning: a high-confidence
    conclusion is, by definition, one the system is already fairly
    sure about; a human checking it adds comparatively little. A
    low-confidence-but-high-severity conclusion is exactly the case
    where human judgment is most needed to resolve the ambiguity
    before deciding whether to act. Ranking by confidence alone (high
    confidence first) would systematically starve the cases that most
    need a human, which defeats the purpose of triage. This is stated
    explicitly because "rank by confidence descending" is the
    intuitive-but-wrong default a less careful design would ship.

RECENCY(a):
    exp(-age_hours(a) / 24.0), exponential decay with 24h half-life-ish
    scale — same decay family as ioc-decay/ioc_decay.py's half-life
    model, applied here to "how stale is this finding" rather than
    "how stale is this indicator." A finding from 5 minutes ago and one
    from 5 days ago should not compete equally for an analyst's
    next-hour attention even at equal severity/confidence.

BLAST_RADIUS(a):
    min(distinct_entity_count(a) / 5.0, 1.0)
    where distinct_entity_count is read from the Blackwell Knowledge
    Graph projection (blackwell-core/knowledge-graph) for this node —
    a conclusion touching 5+ distinct entities (hosts, users, CVEs)
    ranks as having a wider potential blast radius than one touching a
    single entity. This is the one BER signal that depends on another
    Blackwell module's output rather than being self-contained, and
    that dependency is intentional: blast radius is fundamentally a
    graph-connectivity question, and BKG is where that's computed.

----------------------------------------------------------------------
WHY THIS IS A SEPARATE ALGORITHM FROM BCE
----------------------------------------------------------------------
BCE (confidence-engine) and BER answer different questions and should
not be collapsed into one score: "how much do I believe this" and
"how urgently should a human look at this" can point in opposite
directions for the same finding, as the inverted-confidence-term
discussion above makes explicit. Keeping them as two separate,
separately-inspectable numbers lets the Decision Engine (which
consumes both) make that tradeoff visible to an analyst rather than
hiding it inside one conflated score.

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
O(V) to score every ASSERTION/CONCLUSION node, plus one BKG lookup per
node for blast_radius (itself O(1) amortized given a precomputed
entity index). Sorting the final ranked list is O(V log V).

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. Weights are hand-set, same caveat as BRS/BCE — no labeled "analyst
   actually needed to see this first" outcome dataset exists to fit
   against.
2. recency() uses wall-clock age at scoring time, which means a
   ranking snapshot becomes stale the moment time passes; this module
   does not implement live re-ranking, it produces a point-in-time
   priority list.
3. blast_radius via entity count is a crude proxy for true operational
   impact — it does not distinguish "touches 5 low-value test hosts"
   from "touches 5 domain controllers." Asset criticality weighting is
   not implemented (this lab has no asset criticality data source to
   draw from) and is listed as future work.
"""

import json
import os
import sys
import math
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "knowledge-graph"))
from evidence_graph import EvidenceGraph, NodeKind  # noqa: E402
from knowledge_graph import build_knowledge_graph, extract_entities  # noqa: E402

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

WEIGHTS = {
    "severity": 0.35,
    "blast_radius": 0.25,
    "recency": 0.20,
    "confidence_gap": 0.20,
}

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}


@dataclass
class RankedFinding:
    node_id: str
    label: str
    priority: float
    components: dict
    rationale: str


def severity_weight(node) -> float:
    sev = (node.attributes or {}).get("severity", "LOW")
    return SEVERITY_WEIGHT.get(sev, 0.15)


def recency(node) -> float:
    ts = node.timestamp
    if not ts:
        return 0.5  # unknown age, neutral default
    try:
        event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_hours = max(0.0, (now - event_time).total_seconds() / 3600.0)
        return math.exp(-age_hours / 24.0)
    except (ValueError, TypeError):
        return 0.5


def blast_radius(node, entity_count_by_node: dict) -> float:
    count = entity_count_by_node.get(node.node_id, 0)
    return min(count / 5.0, 1.0)


def rank_evidence(graph: EvidenceGraph) -> list[RankedFinding]:
    # Build entity-count-per-node index from the Knowledge Graph projection
    entity_count_by_node: dict[str, int] = {}
    for node in graph.nodes.values():
        ents = extract_entities(node)
        entity_count_by_node[node.node_id] = len(set(e.entity_id for e in ents))

    targets = [n for n in graph.nodes.values()
               if n.kind in (NodeKind.ASSERTION, NodeKind.CONCLUSION)]

    results = []
    for node in targets:
        sev = severity_weight(node)
        conf = max(0.0, min(1.0, node.weight))
        conf_gap = 1.0 - conf  # inverted — see module docstring
        rec = recency(node)
        blast = blast_radius(node, entity_count_by_node)

        priority = (
            WEIGHTS["severity"] * sev
            + WEIGHTS["confidence_gap"] * conf_gap
            + WEIGHTS["recency"] * rec
            + WEIGHTS["blast_radius"] * blast
        )

        rationale = (
            f"severity={sev:.2f}(w{WEIGHTS['severity']}) "
            f"confidence_gap={conf_gap:.2f}(confidence={conf:.2f}, w{WEIGHTS['confidence_gap']}, inverted-by-design) "
            f"recency={rec:.2f}(w{WEIGHTS['recency']}) "
            f"blast_radius={blast:.2f}(entities={entity_count_by_node.get(node.node_id,0)}, w{WEIGHTS['blast_radius']})"
        )

        results.append(RankedFinding(
            node_id=node.node_id, label=node.label, priority=round(priority, 3),
            components={
                "severity": round(sev, 3), "confidence": round(conf, 3),
                "confidence_gap": round(conf_gap, 3), "recency": round(rec, 3),
                "blast_radius": round(blast, 3),
            },
            rationale=rationale,
        ))

    return sorted(results, key=lambda r: -r.priority)


def main():
    graph = EvidenceGraph.load_from_obsidian_outputs()
    if not graph.nodes:
        print("[!] Evidence Graph is empty. Run the OBSIDIAN PROTOCOL pipeline first.")
        sys.exit(1)

    ranked = rank_evidence(graph)

    print("=" * 70)
    print("  BLACKWELL EVIDENCE RANKING (BER) v1.0")
    print("=" * 70)
    print(f"\n  Ranked {len(ranked)} findings by analyst-attention priority\n")
    for i, r in enumerate(ranked, 1):
        print(f"  #{i}  priority={r.priority:.3f}  {r.label}")
        print(f"      {r.rationale}\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "ranked_findings.json")
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in ranked], f, indent=2, ensure_ascii=False)
    print(f"[+] Saved: {out_path}")


if __name__ == "__main__":
    main()
