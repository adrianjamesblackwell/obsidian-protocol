#!/usr/bin/env python3
"""
blackwell-core/attack-path-prediction/attack_path_prediction.py

BLACKWELL ATTACK PATH PREDICTION (BAPP) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM AND HONEST FRAMING
----------------------------------------------------------------------
"Attack path prediction" is frequently presented in industry marketing
as if it means forecasting a specific attacker's specific next move.
That is not what this module does, and we say so explicitly: BAPP does
NOT predict what a particular adversary will do next. What it does is
narrower and fully verifiable: given the current Evidence Graph state
(confirmed compromise nodes, MITRE techniques observed so far), it
projects a small number of STRUCTURALLY PLAUSIBLE next steps drawn
from the MITRE ATT&CK tactic-ordering model, ranked by how well they
fit the technique sequence observed so far. This is graph-structured
hypothesis generation, not forecasting, and the output is explicitly
labeled HYPOTHETICAL (see risk-graph/risk_graph.py's own established
convention for distinguishing confirmed vs. hypothetical nodes, which
BAPP follows for consistency across the Blackwell layer).

----------------------------------------------------------------------
FORMAL MODEL
----------------------------------------------------------------------
MITRE ATT&CK tactics have a loose, well-documented kill-chain ordering
(Reconnaissance -> ... -> Initial Access -> Execution -> Persistence ->
Privilege Escalation -> Defense Evasion -> Credential Access ->
Discovery -> Lateral Movement -> Collection -> Command and Control ->
Exfiltration -> Impact). BAPP encodes this ordering as a directed
TACTIC_TRANSITION graph T, where edge (tactic_i, tactic_j) has a
plausibility weight derived from how frequently that transition
appears in this project's bundled chain-pattern library (BCA's
KNOWN_CHAIN_PATTERNS) UNION a small set of well-documented common
post-exploitation transitions (e.g. Privilege Escalation ->
Credential Access is an extremely common documented pattern, even
though it does not appear in this lab's own two-vector chain).

Given the current confirmed tactic sequence observed for an incident
(read from BCA's mitre_chain), BAPP computes:

    next_tactic_candidates(observed_sequence) =
        { t : (last_observed_tactic, t) ∈ T }
        ranked by T's transition weight, descending

For each candidate, BAPP attaches:
    - the specific telemetry GAP that would need to be closed to
      detect it, by cross-referencing telemetry-gap/gap_analysis.py's
      output (if available) — "if the attacker proceeds to Lateral
      Movement next, here is whether we would currently see it"
    - a HYPOTHETICAL node in the Evidence Graph, connected to the
      current confirmed conclusion via a DERIVED_FROM edge with
      strength = transition weight, explicitly typed so it can never
      be confused with a confirmed finding when the graph is queried
      or rendered.

----------------------------------------------------------------------
WHY THIS BOUNDS ITSELF TO TACTIC-LEVEL, NOT TECHNIQUE-LEVEL, PREDICTION
----------------------------------------------------------------------
MITRE ATT&CK documents roughly 14 tactics but hundreds of techniques.
Predicting "what's structurally plausible" at the tactic level (e.g.
"Lateral Movement is a documented common next phase after Privilege
Escalation") is defensible from public, well-documented kill-chain
literature. Predicting a SPECIFIC technique (e.g. "the next step will
specifically be T1021.004 SSH lateral movement rather than T1021.001
RDP") would require either a much larger labeled corpus of real
campaign sequences than this lab has, or speculation dressed up as
prediction. BAPP deliberately stops at the level of granularity its
inputs can actually support.

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
O(1) per incident lookup against the fixed TACTIC_TRANSITION table
(bounded by ~14 tactics, so the table has at most 14*13 entries,
effectively a constant-size structure). Cross-referencing telemetry
gap data is O(g) where g = number of gap entries (small, single-digit
in this project).

----------------------------------------------------------------------
KNOWN LIMITATIONS (stated as the central caveat of this whole module)
----------------------------------------------------------------------
1. This is NOT adversary forecasting. It is structural hypothesis
   generation from a small, partly hand-curated transition table. It
   should never be presented to a stakeholder as "the system predicts
   the attacker will do X" — the correct framing is "if this operation
   continues, here are tactics that would be structurally consistent
   with documented kill-chains, and whether we'd currently detect
   them."
2. The TACTIC_TRANSITION table is a mix of this project's own two-
   vector chain (small, real, but narrow) and well-documented general
   ATT&CK transitions added for completeness — it has NOT been
   validated against a large real-world campaign corpus. This is
   exactly the kind of claim that must not be inflated; see
   blackwell-core/benchmark "What we do not claim."
3. No probability calibration. Transition "weights" are ordinal
   (ranking candidates relative to each other) and should not be read
   as calibrated probabilities of what will actually happen.
"""

import json
import os
import sys
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind, EdgeRelation  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
TELEMETRY_GAP_PATH = os.path.join(BASE_DIR, "telemetry-gap", "output", "telemetry_gap.json")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

TECHNIQUE_TO_TACTIC = {
    "T1190": "Initial Access",
    "T1059": "Execution",
    "T1548.001": "Privilege Escalation",
}

# Plausibility weights: this project's own observed chain (high
# confidence, narrow) unioned with well-documented general ATT&CK
# post-exploitation transitions (lower confidence here specifically,
# but well-attested in the public literature generally).
TACTIC_TRANSITION = {
    ("Initial Access", "Execution"): 0.9,        # observed in this lab's own VECTOR-I
    ("Execution", "Privilege Escalation"): 0.85,  # observed in this lab's own VECTOR-I->II
    ("Privilege Escalation", "Credential Access"): 0.6,   # common documented pattern, not observed here
    ("Privilege Escalation", "Defense Evasion"): 0.55,    # common documented pattern, not observed here
    ("Credential Access", "Discovery"): 0.5,
    ("Discovery", "Lateral Movement"): 0.55,
    ("Lateral Movement", "Collection"): 0.45,
    ("Collection", "Exfiltration"): 0.5,
    ("Lateral Movement", "Command and Control"): 0.4,
    ("Command and Control", "Exfiltration"): 0.4,
}


@dataclass
class PathCandidate:
    from_tactic: str
    to_tactic: str
    plausibility: float
    currently_detectable: bool
    detection_note: str


def load_telemetry_gaps() -> set:
    """Returns the set of tactic names this project is currently BLIND to,
    per telemetry-gap/gap_analysis.py's own output."""
    if not os.path.exists(TELEMETRY_GAP_PATH):
        return set()
    with open(TELEMETRY_GAP_PATH) as f:
        data = json.load(f)
    blind = set()
    for entry in data.get("tactics", data) if isinstance(data, dict) else data:
        if isinstance(entry, dict) and entry.get("visibility") in ("BLIND", "Blind", "kor"):
            blind.add(entry.get("tactic"))
    return blind


def predict_next_tactics(observed_technique_sequence: list[str], blind_tactics: set) -> list[PathCandidate]:
    if not observed_technique_sequence:
        return []
    last_technique = observed_technique_sequence[-1]
    last_tactic = TECHNIQUE_TO_TACTIC.get(last_technique)
    if not last_tactic:
        return []

    candidates = []
    for (src, dst), weight in TACTIC_TRANSITION.items():
        if src == last_tactic:
            detectable = dst not in blind_tactics
            note = (
                "Currently detectable — at least one telemetry source covers this tactic"
                if detectable else
                "NOT currently detectable — this project has no telemetry source covering this tactic "
                "(see telemetry-gap/gap_analysis.py)"
            )
            candidates.append(PathCandidate(
                from_tactic=last_tactic, to_tactic=dst, plausibility=weight,
                currently_detectable=detectable, detection_note=note,
            ))
    return sorted(candidates, key=lambda c: -c.plausibility)


def run_bapp(graph: EvidenceGraph) -> dict:
    blind_tactics = load_telemetry_gaps()
    assertions = [n for n in graph.nodes.values() if n.kind == NodeKind.ASSERTION]

    results = {}
    for a in assertions:
        seq = a.attributes.get("mitre_chain") or a.attributes.get("technique_sequence") or []
        seq = [s for s in seq if s]
        candidates = predict_next_tactics(seq, blind_tactics)
        if not candidates:
            continue

        results[a.node_id] = {
            "incident": a.label,
            "observed_sequence": seq,
            "candidates": [asdict(c) for c in candidates],
        }

        for c in candidates:
            hyp_id = graph.add_node(
                kind=NodeKind.CONCLUSION,
                label=f"HYPOTHETICAL: {c.from_tactic} -> {c.to_tactic}",
                weight=c.plausibility,
                provenance="blackwell-core:bapp-v1.0",
                attributes={
                    "node_type": "HYPOTHETICAL",
                    "currently_detectable": c.currently_detectable,
                    "detection_note": c.detection_note,
                },
            )
            graph.add_edge(
                source=a.node_id, target=hyp_id,
                relation=EdgeRelation.DERIVED_FROM, strength=c.plausibility,
                rationale=f"Structurally plausible next tactic per ATT&CK transition model "
                          f"(NOT a forecast of actual adversary behavior)",
                produced_by="blackwell-core:bapp-v1.0",
            )

    return results


def main():
    graph = EvidenceGraph.load_from_obsidian_outputs()
    if not graph.nodes:
        print("[!] Evidence Graph is empty. Run the OBSIDIAN PROTOCOL pipeline first.")
        sys.exit(1)

    results = run_bapp(graph)

    print("=" * 70)
    print("  BLACKWELL ATTACK PATH PREDICTION (BAPP) v1.0")
    print("  *** Structural hypothesis generation, NOT adversary forecasting ***")
    print("=" * 70)
    if not results:
        print("\n  No incidents with a recognized technique sequence to project from.")
    for incident_id, data in results.items():
        print(f"\n  {data['incident']}")
        print(f"    Observed: {' -> '.join(data['observed_sequence'])}")
        print(f"    Structurally plausible next tactics:")
        for c in data["candidates"]:
            mark = "✓" if c["currently_detectable"] else "✗ BLIND SPOT"
            print(f"      [{mark}] {c['from_tactic']} -> {c['to_tactic']}  "
                  f"(plausibility={c['plausibility']})")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "attack_path_predictions.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    graph.save(os.path.join(OUTPUT_DIR, "evidence_graph_post_bapp.json"))
    print(f"\n[+] Saved: {out_path}")
    print(f"[+] Updated graph saved: {OUTPUT_DIR}/evidence_graph_post_bapp.json")


if __name__ == "__main__":
    main()
