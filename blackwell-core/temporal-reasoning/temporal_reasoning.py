#!/usr/bin/env python3
"""
blackwell-core/temporal-reasoning/temporal_reasoning.py

BLACKWELL TEMPORAL REASONING (BTR) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
BCA (blackwell-core/correlation-bca) groups events by a fixed time
window and matches the resulting technique sequence against a pattern
library — but it answers only "did this group of events form a known
chain," not "what is the TEMPORAL SHAPE of this operation, and does
that shape itself carry information." Two real attacker behaviors that
BCA's window-based grouping treats identically:

  (a) An automated exploit chain: exploitation step to next step in
      seconds (machine-speed, low variance between steps).
  (b) A human operator manually working through the same technique
      sequence: minutes between steps, high variance, occasional long
      pauses (the operator reading output, deciding next move).

These are operationally very different (automated tooling vs. a human
on the keyboard) and that distinction matters for response — but BCA's
window+pattern-match alone cannot tell them apart; it only sees that
both produced the same technique sequence within the window.

----------------------------------------------------------------------
WHAT BTR ADDS
----------------------------------------------------------------------
For a sequence of evidence nodes ordered by timestamp within an
incident, BTR computes:

  inter_event_intervals: the list of gaps (in seconds) between
      consecutive events.

  tempo_class(intervals):
      MACHINE_SPEED   if median(intervals) < 2s
      RAPID           if 2s <= median(intervals) < 30s
      DELIBERATE       if 30s <= median(intervals) < 300s
      SLOW_AND_LOW      if median(intervals) >= 300s
      (thresholds are stated explicitly as heuristic boundaries, not
       derived from any labeled dataset of attacker behavior — see
       Known Limitations)

  regularity(intervals):
      1 - (stdev(intervals) / (mean(intervals) + epsilon))
      clipped to [0,1]. High regularity (low relative variance)
      is associated with scripted/automated execution; low
      regularity (high relative variance) is associated with manual,
      human-paced operation. This is the same coefficient-of-variation
      idea used broadly in process-monitoring fields, applied here to
      attacker dwell-time between technique-bearing events; we present
      it as an adaptation of a standard statistical tool; not as a
      novel statistical method.

  anomalous_gaps(intervals, threshold_factor=3.0):
      Any single gap > threshold_factor * median(intervals) is flagged
      as an anomalous pause — a candidate point where the operator
      may have been doing something not captured by current
      telemetry (researching, waiting for a C2 callback, working
      around a defense). This does not claim to KNOW what happened in
      the gap, only that the gap is statistically unusual relative to
      the rest of the sequence and worth an analyst's attention. This
      is the temporal analogue of telemetry-gap/gap_analysis.py's
      "what are we blind to" question, here applied within a single
      incident's timeline rather than across the whole module
      footprint.

----------------------------------------------------------------------
RELATIONSHIP TO BCA AND THE EVIDENCE GRAPH
----------------------------------------------------------------------
BTR reads the same ASSERTION nodes BCA produces (each carrying its
member RAW_EVENT nodes via SUPPORTS edges) and adds a
TEMPORALLY_PRECEDES edge between each consecutive pair of member
events, annotated with the interval and whether it was flagged
anomalous. This means the "is this gap odd" judgment becomes part of
the Evidence Graph itself, inspectable by the Decision Engine, rather
than a number that only existed inside this module's stdout.

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
O(n log n) per incident (dominated by sorting events by timestamp),
O(1) additional work per consecutive pair for interval computation.
Total across all incidents: O(N log N) where N is total raw event
count, since incidents partition the event set.

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. Tempo class thresholds (2s/30s/300s) are heuristic boundaries
   chosen by inspection of this project's own VECTOR-I/II timing, not
   derived from a labeled corpus of automated-vs-manual attacker
   behavior. They should be treated as a starting point, not a
   validated classifier.
2. regularity() assumes intervals are roughly continuous and that
   coefficient-of-variation is a meaningful descriptor for n as small
   as 2-3 intervals (common in a short lab chain). At very small n
   this statistic is noisy — the module does not suppress or flag low-
   n unreliability, which a production version should.
3. anomalous_gaps() flags statistical outliers, not causal
   explanations. A flagged gap could mean "operator was thinking," "C2
   beacon interval," or "completely unrelated activity that happened
   to fall in this actor-key + window grouping" — BTR does not and
   cannot distinguish these without additional evidence.
"""

import json
import os
import sys
import statistics
from dataclasses import dataclass, asdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind, EdgeRelation  # noqa: E402

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


@dataclass
class TemporalProfile:
    incident_id: str
    event_count: int
    intervals_seconds: list
    median_interval: float
    tempo_class: str
    regularity: float
    anomalous_gap_indices: list
    rationale: str


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def tempo_class(median_interval: float) -> str:
    if median_interval < 2:
        return "MACHINE_SPEED"
    if median_interval < 30:
        return "RAPID"
    if median_interval < 300:
        return "DELIBERATE"
    return "SLOW_AND_LOW"


def regularity(intervals: list[float]) -> float:
    if len(intervals) < 2:
        return 1.0  # not enough data to call it irregular; treat as neutral/high
    mean = statistics.mean(intervals)
    if mean == 0:
        return 1.0
    stdev = statistics.pstdev(intervals)
    cv = stdev / (mean + 1e-9)
    return max(0.0, min(1.0, 1.0 - cv))


def anomalous_gaps(intervals: list[float], threshold_factor: float = 3.0) -> list[int]:
    if len(intervals) < 2:
        return []
    med = statistics.median(intervals)
    if med == 0:
        med = 1e-6
    return [i for i, gap in enumerate(intervals) if gap > threshold_factor * med]


def analyze_incident(incident_id: str, sorted_events: list) -> TemporalProfile:
    timestamps = [parse_iso(e.timestamp) for e in sorted_events]
    intervals = [
        (timestamps[i + 1] - timestamps[i]).total_seconds()
        for i in range(len(timestamps) - 1)
    ]
    median_interval = statistics.median(intervals) if intervals else 0.0
    tc = tempo_class(median_interval)
    reg = regularity(intervals)
    anomalies = anomalous_gaps(intervals)

    rationale = (
        f"{len(sorted_events)} events, median gap {median_interval:.1f}s -> {tc}, "
        f"regularity={reg:.2f} ({'scripted-looking' if reg > 0.7 else 'human-paced-looking' if reg < 0.4 else 'mixed'}), "
        f"{len(anomalies)} anomalous gap(s) flagged"
    )

    return TemporalProfile(
        incident_id=incident_id,
        event_count=len(sorted_events),
        intervals_seconds=[round(i, 2) for i in intervals],
        median_interval=round(median_interval, 2),
        tempo_class=tc,
        regularity=round(reg, 3),
        anomalous_gap_indices=anomalies,
        rationale=rationale,
    )


def run_btr(graph: EvidenceGraph) -> list[TemporalProfile]:
    assertions = [n for n in graph.nodes.values() if n.kind == NodeKind.ASSERTION]
    profiles = []
    for a in assertions:
        member_edges = graph.in_edges(a.node_id)
        member_nodes = [
            graph.nodes[e.source] for e in member_edges
            if e.relation == EdgeRelation.SUPPORTS and e.source in graph.nodes
            and graph.nodes[e.source].kind == NodeKind.RAW_EVENT
        ]
        member_nodes = [n for n in member_nodes if n.timestamp]
        member_nodes.sort(key=lambda n: n.timestamp)
        if len(member_nodes) < 1:
            continue
        profile = analyze_incident(a.node_id, member_nodes)
        profiles.append(profile)

        # Write TEMPORALLY_PRECEDES edges back into the graph
        for i in range(len(member_nodes) - 1):
            is_anomalous = i in profile.anomalous_gap_indices
            graph.add_edge(
                source=member_nodes[i].node_id, target=member_nodes[i + 1].node_id,
                relation=EdgeRelation.TEMPORALLY_PRECEDES,
                strength=0.3 if is_anomalous else 0.9,
                rationale=(
                    f"Gap={profile.intervals_seconds[i]:.1f}s "
                    f"({'ANOMALOUS — flagged for review' if is_anomalous else 'within expected range'})"
                ),
                produced_by="blackwell-core:btr-v1.0",
            )
    return profiles


def main():
    graph = EvidenceGraph.load_from_obsidian_outputs()
    if not graph.nodes:
        print("[!] Evidence Graph is empty. Run the OBSIDIAN PROTOCOL pipeline first.")
        sys.exit(1)

    profiles = run_btr(graph)

    print("=" * 70)
    print("  BLACKWELL TEMPORAL REASONING (BTR) v1.0")
    print("=" * 70)
    print(f"\n  Analyzed {len(profiles)} incident timelines\n")
    for p in profiles:
        print(f"  {p.incident_id}  [{p.tempo_class}]  regularity={p.regularity}")
        print(f"    {p.rationale}\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "temporal_profiles.json")
    with open(out_path, "w") as f:
        json.dump([asdict(p) for p in profiles], f, indent=2, ensure_ascii=False)

    graph.save(os.path.join(OUTPUT_DIR, "evidence_graph_post_btr.json"))
    print(f"[+] Profiles saved: {out_path}")
    print(f"[+] Updated graph saved: {OUTPUT_DIR}/evidence_graph_post_btr.json")


if __name__ == "__main__":
    main()
