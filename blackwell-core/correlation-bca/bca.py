#!/usr/bin/env python3
"""
blackwell-core/correlation-bca/bca.py

BLACKWELL CORRELATION ALGORITHM (BCA) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
This is the named, versioned, formally-specified successor to
correlation-engine/correlate.py. The underlying idea is the same
(group raw events into incidents using actor identity + time window +
known kill-chain pattern matching) — BCA's contribution is:

  1. A formal specification (below) instead of an implicit one.
  2. Operating on the Blackwell Evidence Graph rather than a flat
     event list, so correlation decisions become first-class
     ASSERTION nodes with SUPPORTS edges back to their raw evidence
     (queryable, auditable, revisable) instead of a side json file.
  3. An explicit, tunable scoring function (Section 3) instead of
     the three fixed confidence buckets (20/40/70/95) used in v0.
  4. A documented evaluation protocol (Section 5) so the algorithm's
     behavior can be benchmarked against itself across versions,
     and against ablations — see blackwell-core/benchmark.

correlation-engine/correlate.py is NOT removed or replaced. It remains
the simple, dependency-free reference implementation. BCA is the
research-grade formalization that operates on BEG and that future
work (v1.1, v2) will extend.

----------------------------------------------------------------------
1. FORMAL PROBLEM STATEMENT
----------------------------------------------------------------------
Given a set of evidence nodes E = {e_1, ..., e_n} in a Blackwell
Evidence Graph, each with:
    actor(e)      -> an actor key (src_ip or user)
    t(e)          -> a timestamp
    technique(e)  -> a MITRE ATT&CK technique ID, possibly null

find a partition of E into incident groups I = {I_1, ..., I_m} such
that for each I_k:
    (a) all e in I_k share the same actor(e)               [actor closure]
    (b) max(t(e) for e in I_k) - min(t(e) for e in I_k)
            is coverable by a chain of consecutive gaps,
            each <= window_seconds                          [temporal closure]
    (c) the ordered sequence of technique(e) for e in I_k
            is assigned a confidence c(I_k) via the scoring
            function in Section 3.

This is a single-link temporal clustering problem (constraint b is
equivalent to single-link/MST clustering with a distance threshold)
composed with a sequence-matching confidence assignment. We state this
explicitly because it clarifies what BCA is NOT: it is not a general
multi-actor graph clustering algorithm, and it does not claim to find
correlations between two different actor_keys (e.g. a coordinated
multi-host campaign) — see Known Limitations #1.

----------------------------------------------------------------------
2. ALGORITHM (PSEUDOCODE)
----------------------------------------------------------------------
    BCA(E, window_seconds, patterns):
        groups_by_actor <- partition E by actor(e)
        incidents <- []
        for actor, events in groups_by_actor:
            sort events by t(e)
            current <- [events[0]]
            for e in events[1:]:
                if t(e) - t(current.last) <= window_seconds:
                    current.append(e)
                else:
                    incidents.append(SCORE(current, patterns))
                    current <- [e]
            incidents.append(SCORE(current, patterns))
        return incidents

    SCORE(group, patterns):
        seq <- [technique(e) for e in group if technique(e) is not null]
        return match_confidence(seq, patterns)   # Section 3

Runtime: sorting dominates at O(n log n) per actor group; the single
pass that follows is O(n). Total: O(n log n) where n = |E|. This is
unchanged from the v0 reference implementation — BCA's contribution
is the scoring function and the graph-native output, not asymptotic
improvement, and we are explicit about that rather than overstating
it.

----------------------------------------------------------------------
3. CONFIDENCE SCORING FUNCTION
----------------------------------------------------------------------
Given an observed technique sequence `seq` and a library of known
chain patterns P = {p_1, ..., p_k} (each p_i is itself a technique
sequence with an associated severity), v1.0 uses:

    match_confidence(seq, P):
        if |seq| == 0:  return (LOW, 0.0)
        if |seq| == 1:  return (LOW, 0.20)     # single technique, no chain
        if seq exactly equals some p_i:
            return (p_i.severity, 0.95)         # exact match
        if seq is a strict prefix of some p_i (|seq| < |p_i|):
            return (MEDIUM, 0.70)               # in-progress attack
        else:
            return (MEDIUM, 0.40)               # multiple techniques,
                                                 # unrecognized chain

This is a deliberately simple, fully explainable step function — see
Section 4 for why, and Known Limitations #2 for what it gives up by
being simple. It is the same scoring logic as the v0 reference
implementation, restated formally; BCA v1.0's job is the
formalization and graph integration, not yet a new scoring function.
v1.1 (Confidence Engine integration, see
blackwell-core/confidence-engine) replaces this step function with a
continuous, multi-signal score — this module's `match_confidence` is
the documented baseline that the Confidence Engine's improvement is
measured against.

----------------------------------------------------------------------
4. WHY A STEP FUNCTION AND NOT A CONTINUOUS SCORE (v1.0 design choice)
----------------------------------------------------------------------
A continuous score (e.g. cosine similarity over technique sequences,
or a learned sequence model) would handle partial/noisy matches more
gracefully, but would also be harder for an analyst to audit at a
glance — "70%" from a continuous model requires trusting the model;
"70%, because this is a recognized prefix of a known chain" is
self-explanatory. v1.0 prioritizes explainability over coverage. This
project's stated position (consistent with risk-engine/README.md and
ioc-decay/README.md) is: ship the explainable simple model first,
document its limitations precisely, and treat the move to a learned
or continuous model as a measured improvement with its own
benchmark — not a default starting point. See Section 5.

----------------------------------------------------------------------
5. EVALUATION PROTOCOL
----------------------------------------------------------------------
BCA is evaluated three ways (see blackwell-core/benchmark for the
implementation and current numbers):

  (a) Reduction ratio: 1 - |incidents| / |raw events|, on this
      project's own VECTOR-I/II telemetry. This is a real, measured
      number from this project's own data — not a claim about
      production SOC volumes.
  (b) Ablation: BCA with the pattern library vs. BCA with an empty
      pattern library (i.e. correlation by time+actor alone, no
      chain-matching). This isolates how much of BCA's value comes
      from temporal/actor grouping alone vs. from kill-chain pattern
      recognition specifically.
  (c) Synthetic label agreement: a hand-labeled synthetic event set
      (blackwell-core/benchmark/fixtures/synthetic_events.json) with
      known ground-truth incident boundaries, scored against
      precision/recall on incident boundary detection.
      This project does NOT claim a comparison against commercial
      SIEM correlation engines (Splunk ES, Microsoft Sentinel, Elastic
      Security) because no such comparison was run, and reporting one
      without running it would be fabricated benchmarking — see
      blackwell-core/benchmark/README.md "What we do not claim."

----------------------------------------------------------------------
6. KNOWN LIMITATIONS
----------------------------------------------------------------------
1. Single-actor scope. BCA groups events by one actor key at a time;
   it does not detect coordinated multi-actor campaigns (e.g. the
   same operator pivoting through multiple compromised accounts with
   different src_ips). That is a genuinely harder correlation problem
   (entity resolution across actor keys) and is explicitly out of
   scope for v1.0 — see Future Work in docs/research-findings.md.
2. The pattern library (KNOWN_CHAIN_PATTERNS) is hand-curated and, in
   this project, encodes this project's own VECTOR-I/II chain. A
   production deployment would derive this library from MITRE
   ATT&CK's published group/campaign data or from organization-specific
   historical incidents — the algorithm is generic, the bundled
   pattern library is a worked example, not a claim of general
   coverage.
3. Fixed window_seconds (default 300s) is a single global parameter.
   A slow, low-and-slow operation spanning hours would not be
   detected as one incident under v1.0. Adaptive/multi-scale windowing
   is listed as future work, not attempted here.
"""

import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind, EdgeRelation  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
BEG_PATH = os.path.join(BASE_DIR, "blackwell-core", "evidence-graph", "output", "evidence_graph.json")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
DEFAULT_WINDOW_SECONDS = 300

KNOWN_CHAIN_PATTERNS = [
    {"name": "VECTOR-I: Web RCE Kill-Chain", "sequence": ["T1190", "T1059"], "severity": "HIGH"},
    {"name": "VECTOR-I -> VECTOR-II: Full Chain (RCE -> PrivEsc)",
     "sequence": ["T1190", "T1059", "T1548.001"], "severity": "CRITICAL"},
    {"name": "VECTOR-II: Local Privilege Escalation", "sequence": ["T1548.001"], "severity": "HIGH"},
]


@dataclass
class BcaScore:
    confidence: float
    severity: str
    matched_pattern: str | None
    rationale: str


def match_confidence(seq: list[str], patterns: list[dict] = KNOWN_CHAIN_PATTERNS) -> BcaScore:
    """Section 3 of the module docstring, implemented literally."""
    if len(seq) == 0:
        return BcaScore(0.0, "LOW", None, "No technique-bearing events in group")
    if len(seq) == 1:
        return BcaScore(0.20, "LOW", None, "Single technique observed, no chain to evaluate")

    for p in patterns:
        if seq == p["sequence"]:
            return BcaScore(0.95, p["severity"], p["name"],
                             f"Exact match against known chain pattern: {' -> '.join(seq)}")

    for p in patterns:
        L = len(seq)
        if p["sequence"][:L] == seq and L < len(p["sequence"]):
            return BcaScore(0.70, "MEDIUM", p["name"],
                             f"Observed sequence is a prefix of '{p['name']}' "
                             f"— attack may be in progress")

    return BcaScore(0.40, "MEDIUM", None,
                     f"Multiple techniques observed ({', '.join(seq)}) "
                     f"but sequence does not match any known chain pattern")


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def run_bca(graph: EvidenceGraph, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list[dict]:
    """
    Implements the pseudocode of Section 2, but reads RAW_EVENT nodes
    from a Blackwell Evidence Graph instead of a flat ndjson file, and
    writes its output back into the same graph as new ASSERTION nodes
    with SUPPORTS edges — this is the structural difference from
    correlation-engine/correlate.py.
    """
    raw_events = [n for n in graph.nodes.values() if n.kind == NodeKind.RAW_EVENT]

    by_actor: dict[str, list] = {}
    for n in raw_events:
        attrs = n.attributes
        extra = attrs.get("extra", {})
        if "src_ip" in extra:
            key = f"ip:{extra['src_ip']}"
        elif attrs.get("user"):
            key = f"user:{attrs['user']}"
        else:
            key = f"host:{attrs.get('host', 'unknown')}"
        by_actor.setdefault(key, []).append(n)

    results = []
    for actor_key, nodes in by_actor.items():
        nodes = [n for n in nodes if n.timestamp]
        nodes.sort(key=lambda n: n.timestamp)

        group = []
        for n in nodes:
            if not group:
                group.append(n)
                continue
            delta = (parse_iso(n.timestamp) - parse_iso(group[-1].timestamp)).total_seconds()
            if 0 <= delta <= window_seconds:
                group.append(n)
            else:
                results.append(_finalize_group(graph, actor_key, group))
                group = [n]
        if group:
            results.append(_finalize_group(graph, actor_key, group))

    return results


def _finalize_group(graph: EvidenceGraph, actor_key: str, group: list) -> dict:
    seq = [g.attributes.get("mitre_technique") for g in group if g.attributes.get("mitre_technique")]
    cve_chain = sorted(set(g.attributes.get("cve") for g in group if g.attributes.get("cve")))
    score = match_confidence(seq)

    assertion_id = graph.add_node(
        kind=NodeKind.ASSERTION,
        label=f"BCA incident: {actor_key} ({score.severity})",
        weight=score.confidence,
        provenance="blackwell-core:bca-v1.0",
        timestamp=group[0].timestamp,
        attributes={
            "actor_key": actor_key,
            "technique_sequence": seq,
            "cve_chain": cve_chain,
            "matched_pattern": score.matched_pattern,
            "severity": score.severity,
            "raw_event_count": len(group),
        },
    )
    for n in group:
        graph.add_edge(
            source=n.node_id, target=assertion_id,
            relation=EdgeRelation.SUPPORTS, strength=score.confidence,
            rationale="Grouped by BCA v1.0 actor+window+chain match",
            produced_by="blackwell-core:bca-v1.0",
        )

    return {
        "incident_id": assertion_id,
        "actor_key": actor_key,
        "confidence": score.confidence,
        "severity": score.severity,
        "matched_pattern": score.matched_pattern,
        "rationale": score.rationale,
        "raw_event_count": len(group),
        "technique_sequence": seq,
    }


def main():
    window = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WINDOW_SECONDS

    if not os.path.exists(BEG_PATH):
        print(f"[!] Evidence Graph not found at {BEG_PATH}")
        print("[!] Run first: python3 blackwell-core/evidence-graph/evidence_graph.py")
        sys.exit(1)

    graph = EvidenceGraph.load_from_obsidian_outputs()
    incidents = run_bca(graph, window)

    print("=" * 70)
    print("  BLACKWELL CORRELATION ALGORITHM (BCA) v1.0")
    print("=" * 70)
    raw_count = len([n for n in graph.nodes.values() if n.kind == NodeKind.RAW_EVENT])
    print(f"\n  Raw events:        {raw_count}")
    print(f"  BCA incidents:     {len(incidents)}")
    if raw_count > 0:
        reduction = (1 - len(incidents) / raw_count) * 100
        print(f"  Reduction ratio:   {reduction:.0f}%")
    print("\n  --- INCIDENTS ---\n")
    for inc in sorted(incidents, key=lambda i: -i["confidence"]):
        print(f"  [{inc['severity']:8s}] confidence={inc['confidence']:.2f}  actor={inc['actor_key']}")
        print(f"    Pattern: {inc['matched_pattern'] or '(unmatched)'}")
        print(f"    {inc['rationale']}")
        print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "bca_incidents.json")
    with open(out_path, "w") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)

    graph.save(os.path.join(OUTPUT_DIR, "evidence_graph_post_bca.json"))
    print(f"[+] Incidents saved: {out_path}")
    print(f"[+] Updated graph saved: {OUTPUT_DIR}/evidence_graph_post_bca.json")


if __name__ == "__main__":
    main()
