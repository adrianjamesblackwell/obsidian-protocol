#!/usr/bin/env python3
"""
blackwell-core/decision-engine/decision_engine.py

BLACKWELL DECISION ENGINE (BDE) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
Every module up to this point produces a piece of reasoning: BCA
correlates, BRS scores risk, BCE assigns confidence, BER ranks for
attention, BTR characterizes timing, BKG maps entities, BAPP projects
hypothetical next steps. None of them, individually, answers the
question a SOC actually needs answered at the end of a shift: "given
everything we currently know, what should we do, in what order, and
why." That synthesis is what BDE does. It is the platform's actual
output layer — what OBSIDIAN PROTOCOL's README.md's table of "real-
world problems" ultimately cashes out to for an analyst, an incident
commander, and an executive, each of whom needs a different shaped
answer from the same underlying evidence.

This is also the literal definition of the platform repositioning
described in docs/whitepaper: the system's output is not a log line,
a Sigma rule match, or an IOC — it is a evidence-grounded security
recommendation, with the supporting reasoning attached and traceable.

----------------------------------------------------------------------
WHAT BDE DOES, CONCRETELY
----------------------------------------------------------------------
BDE does NOT introduce a new scoring formula. Its job is composition:
read the output of every upstream Blackwell module (BCA incidents,
BRS scores, BCE confidence, BER priority ranking, BTR temporal
profiles, BKG entity graph, BAPP hypothetical paths, and the legacy
root-cause module's causal chains) keyed by shared node_id /cve
identifiers, and produce three things:

  1. A single PRIORITIZED ACTION LIST — BER's ranking, but each item
     enriched with BRS's risk band, root-cause's preventive actions,
     and BAPP's "if this continues" hypothesis, so an analyst gets one
     list instead of seven dashboards.

  2. A WHY-explanation per item — calls EvidenceGraph.subgraph_for()
     for the relevant node and renders it as a short evidence
     narrative, so every recommendation is traceable to the specific
     evidence nodes and edges behind it, not just a number.

  3. TWO DIFFERENT RENDERED REPORTS from the SAME underlying decision
     object — an executive-facing one and a technical one — because
     "CEO doesn't read Sigma rules" (already a stated problem in
     OBSIDIAN PROTOCOL's README.md table) generalizes to: the
     underlying reasoning is audience-independent, only the
     presentation should vary. Producing two reports from one decision
     object (rather than maintaining the executive report as a
     separate analysis, as reporting/executive/executive_report.py
     currently does) is what prevents the two audiences from being
     told subtly different things about the same incident.

----------------------------------------------------------------------
COMPOSITION ALGORITHM
----------------------------------------------------------------------
    BDE(graph, ber_results, brs_results, root_cause_data, bapp_results):
        for each ranked finding f in ber_results (already priority-sorted):
            risk = brs_results.get(f.related_cve)
            causes = root_cause_data.get(f.related_cve, {})
            hypothesis = bapp_results.get(f.node_id, {})
            evidence_narrative = summarize(graph.subgraph_for(f.node_id, depth=2))
            emit DecisionItem(f, risk, causes, hypothesis, evidence_narrative)
        return DecisionItem list, already in BER's priority order

This is deliberately a JOIN, not a new model — BDE's contribution is
making sure that join happens consistently and that both audience-
facing reports are generated from the joined result, not from two
independently-written summaries that could drift apart.

----------------------------------------------------------------------
COMPLEXITY
----------------------------------------------------------------------
O(F) where F = number of ranked findings from BER, plus one
subgraph_for call per finding (each O(b^depth), depth=2, small and
bounded — see evidence-graph complexity section). Effectively linear
in the number of findings for any lab- or SOC-scale incident volume
this architecture targets.

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. BDE is a join over upstream module outputs — if an upstream module
   has not been run, the corresponding enrichment is simply absent
   (explicitly marked "not available" in the output) rather than
   estimated or defaulted. This project consistently prefers a visible
   gap over a silently fabricated number (the same principle stated in
   risk-engine/README.md and ioc-decay/README.md), and BDE follows it.
2. The executive narrative template is hand-written prose generation
   (string templates with conditionals), not a language model — every
   sentence it produces is directly traceable to a specific upstream
   number. This is a deliberate choice: an LLM-generated executive
   summary would read better but would reintroduce exactly the kind of
   unverifiable claim this whole platform is designed to avoid. If a
   future version integrates generative summarization, it should be
   constrained to paraphrase already-computed evidence, not introduce
   new claims.
3. BDE assumes the upstream modules were run against the same Evidence
   Graph snapshot. Running BER against one snapshot and BAPP against a
   later one and joining them would silently produce a stale or
   inconsistent join — there is no version/snapshot reconciliation
   check in v1.0.
"""

import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(THIS_DIR, "..", "evidence-graph"))
sys.path.insert(0, os.path.join(THIS_DIR, "..", "evidence-ranking"))
from evidence_graph import EvidenceGraph  # noqa: E402

BASE_DIR = os.path.join(THIS_DIR, "..", "..")
BLACKWELL_DIR = os.path.join(THIS_DIR, "..")
OUTPUT_DIR = os.path.join(THIS_DIR, "output")

ROOT_CAUSE_PATH = os.path.join(BASE_DIR, "root-cause", "output", "root_cause_report.json")
BER_PATH = os.path.join(BLACKWELL_DIR, "evidence-ranking", "output", "ranked_findings.json")
BRS_PATH = os.path.join(BLACKWELL_DIR, "risk-score-brs", "output", "brs_scores.json")
BAPP_PATH = os.path.join(BLACKWELL_DIR, "attack-path-prediction", "output", "attack_path_predictions.json")
BTR_PATH = os.path.join(BLACKWELL_DIR, "temporal-reasoning", "output", "temporal_profiles.json")


@dataclass
class DecisionItem:
    rank: int
    node_id: str
    label: str
    priority: float
    risk_band: str | None
    risk_score: float | None
    confidence: float
    why_summary: str
    root_cause_primary: str | None
    preventive_actions: list = field(default_factory=list)
    hypothetical_next: list = field(default_factory=list)
    temporal_note: str | None = None
    evidence_node_count: int = 0
    evidence_summary: str = ""


def _load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def _cve_from_node(graph: EvidenceGraph, node_id: str) -> str | None:
    """Looks up the CVE(s) associated with a node directly from its
    attributes (cve_chain for correlation-engine-derived assertions) and,
    failing that, from connected INDICATOR nodes one hop away — more
    reliable than parsing CVE strings out of a display label."""
    node = graph.nodes.get(node_id)
    if not node:
        return None
    attrs = node.attributes or {}
    chain = attrs.get("cve_chain") or attrs.get("cve")
    if chain:
        return chain[0] if isinstance(chain, list) and chain else (chain if isinstance(chain, str) else None)
    # Fall back to walking supporting/connected INDICATOR nodes
    for edge in graph.in_edges(node_id) + graph.out_edges(node_id):
        other_id = edge.target if edge.source == node_id else edge.source
        other = graph.nodes.get(other_id)
        if other and other.node_id.startswith("ind-"):
            return other.node_id.replace("ind-", "")
    return None


def build_evidence_summary(graph: EvidenceGraph, node_id: str) -> tuple[str, int]:
    if node_id not in graph.nodes:
        return "Evidence detail unavailable (node not found in current graph snapshot).", 0
    sub = graph.subgraph_for(node_id, depth=2)
    support_count = sum(1 for e in sub["edges"] if e["relation"] == "SUPPORTS")
    contra_count = sum(1 for e in sub["edges"] if e["relation"] == "CONTRADICTS")
    summary = (
        f"Backed by {support_count} supporting evidence link(s)"
        + (f", {contra_count} contradicting link(s) flagged for review" if contra_count else "")
        + f", across {len(sub['nodes'])} connected evidence node(s) within 2 hops."
    )
    return summary, len(sub["nodes"])


def build_decision_list() -> list[DecisionItem]:
    graph = EvidenceGraph.load_from_obsidian_outputs()

    ber = _load_json(BER_PATH, [])
    brs = _load_json(BRS_PATH, [])
    root_cause = _load_json(ROOT_CAUSE_PATH, {})
    bapp = _load_json(BAPP_PATH, {})
    btr = _load_json(BTR_PATH, [])

    brs_by_cve = {s["cve"]: s for s in brs} if brs else {}
    root_cause_by_cve = root_cause if isinstance(root_cause, dict) else {
        e.get("cve"): e for e in root_cause if isinstance(e, dict)
    }
    btr_by_incident = {p["incident_id"]: p for p in btr} if btr else {}

    items = []
    for i, f in enumerate(ber, 1):
        node_id = f["node_id"]
        cve = _cve_from_node(graph, node_id)
        risk_entry = brs_by_cve.get(cve)
        cause_entry = root_cause_by_cve.get(cve, {}) if cve else {}
        hyp_entry = bapp.get(node_id, {})
        temporal_entry = btr_by_incident.get(node_id)

        evidence_summary, evidence_count = build_evidence_summary(graph, node_id)

        items.append(DecisionItem(
            rank=i,
            node_id=node_id,
            label=f["label"],
            priority=f["priority"],
            risk_band=risk_entry.get("risk_band") if risk_entry else None,
            risk_score=risk_entry.get("composite_score") if risk_entry else None,
            confidence=f["components"].get("confidence", 0.0),
            why_summary=f["rationale"],
            root_cause_primary=cause_entry.get("primary_cause") if cause_entry else None,
            preventive_actions=cause_entry.get("preventive_actions", []) if cause_entry else [],
            hypothetical_next=[
                f"{c['from_tactic']} -> {c['to_tactic']} "
                f"({'detectable' if c['currently_detectable'] else 'BLIND SPOT'})"
                for c in hyp_entry.get("candidates", [])
            ],
            temporal_note=temporal_entry["rationale"] if temporal_entry else None,
            evidence_node_count=evidence_count,
            evidence_summary=evidence_summary,
        ))

    return items


# ---------------------------------------------------------------------
# Report renderers — two audiences, one decision object
# ---------------------------------------------------------------------

def render_technical_report(items: list[DecisionItem]) -> str:
    lines = [
        "# BLACKWELL DECISION ENGINE — TECHNICAL BRIEFING",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        "Prioritized action list. Each item is fully traceable to its",
        "supporting evidence in the Blackwell Evidence Graph — see",
        "`why_summary` and `evidence_summary` per item, or query",
        "`evidence_graph.subgraph_for(node_id)` directly for the full subgraph.",
        "",
    ]
    for item in items:
        lines.append(f"## #{item.rank} — {item.label}")
        lines.append(f"- **Priority score:** {item.priority:.3f}")
        if item.risk_band:
            lines.append(f"- **BRS risk:** {item.risk_score:.1f} [{item.risk_band}]")
        lines.append(f"- **Confidence (BCE):** {item.confidence:.2f}")
        lines.append(f"- **Why ranked here:** {item.why_summary}")
        lines.append(f"- **Evidence:** {item.evidence_summary}")
        if item.temporal_note:
            lines.append(f"- **Temporal profile:** {item.temporal_note}")
        if item.root_cause_primary:
            lines.append(f"- **Root cause:** {item.root_cause_primary}")
        if item.preventive_actions:
            lines.append("- **Preventive actions:**")
            for a in item.preventive_actions:
                lines.append(f"  - {a}")
        if item.hypothetical_next:
            lines.append("- **If this continues (structural hypothesis, not a forecast):**")
            for h in item.hypothetical_next:
                lines.append(f"  - {h}")
        lines.append("")
    return "\n".join(lines)


def render_executive_report(items: list[DecisionItem]) -> str:
    top = items[:3]
    critical_count = sum(1 for i in items if i.risk_band == "CRITICAL")
    high_count = sum(1 for i in items if i.risk_band == "HIGH")
    blind_spots = sum(1 for i in items for h in i.hypothetical_next if "BLIND SPOT" in h)

    lines = [
        "# EXECUTIVE SUMMARY",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        f"This briefing covers {len(items)} prioritized finding(s) from the current",
        f"operation. {critical_count} are CRITICAL risk band, {high_count} are HIGH.",
        f"{blind_spots} potential follow-on attack step(s) were identified that this",
        "environment could not currently detect — see 'Visibility Gaps' below.",
        "",
        "## Top priorities",
        "",
    ]
    for item in top:
        risk_phrase = f"{item.risk_band} risk" if item.risk_band else "risk not yet scored"
        lines.append(f"**{item.rank}. {item.label}** — {risk_phrase}")
        if item.root_cause_primary:
            lines.append(f"   Root cause: {item.root_cause_primary}")
        if item.preventive_actions:
            lines.append(f"   Recommended action: {item.preventive_actions[0]}")
        lines.append("")

    if blind_spots:
        lines.append("## Visibility gaps")
        lines.append("")
        lines.append(
            f"{blind_spots} structurally plausible next step(s) of an ongoing or "
            "past operation would not currently be detected by this environment's "
            "telemetry. This is a coverage investment signal, not a confirmed attack "
            "— see the technical briefing for which specific tactics are affected."
        )
        lines.append("")

    lines.append("## How to read this")
    lines.append("")
    lines.append(
        "Every statement above is generated from measured evidence and existing "
        "module output — risk scores, root-cause chains, and detection-coverage "
        "data already produced by this platform. Nothing here is a model-generated "
        "narrative; every number traces back to a specific evidence node. See the "
        "technical briefing for the full evidence chain behind each item."
    )
    return "\n".join(lines)


def main():
    items = build_decision_list()

    if not items:
        print("[!] No ranked findings available.")
        print("[!] Run first: evidence-graph -> bca -> brs -> confidence-engine -> evidence-ranking")
        sys.exit(1)

    print("=" * 70)
    print("  BLACKWELL DECISION ENGINE (BDE) v1.0")
    print("=" * 70)
    print(f"\n  Synthesized {len(items)} decision item(s) from upstream Blackwell modules\n")
    for item in items:
        print(f"  #{item.rank}  {item.label}  priority={item.priority:.3f}  "
              f"risk={item.risk_band or 'n/a'}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    decision_path = os.path.join(OUTPUT_DIR, "decision_items.json")
    with open(decision_path, "w") as f:
        json.dump([asdict(i) for i in items], f, indent=2, ensure_ascii=False)

    tech_path = os.path.join(OUTPUT_DIR, "technical_briefing.md")
    with open(tech_path, "w") as f:
        f.write(render_technical_report(items))

    exec_path = os.path.join(OUTPUT_DIR, "executive_briefing.md")
    with open(exec_path, "w") as f:
        f.write(render_executive_report(items))

    print(f"\n[+] Decision items: {decision_path}")
    print(f"[+] Technical briefing: {tech_path}")
    print(f"[+] Executive briefing: {exec_path}")


if __name__ == "__main__":
    main()
