#!/usr/bin/env python3
"""
risk-graph/risk_graph.py

OBSIDIAN PROTOCOL — Risk Graph (Attack Path Visualization)

REAL-WORLD PROBLEM: Risk reports are usually flat tables
("CVE-X: High Risk"). That doesn't show how an attack ACTUALLY
travels — from which asset to which asset, by which step. For
management and security architects, the most valuable question is
often "how does the attacker get from here to there" — that's a
GRAPH question, not a table question.

SOLUTION: this engine combines correlation-engine + risk-engine +
telemetry output into a directed graph (DAG):

  Internet -> Apache (VECTOR-I) -> Shell -> PrivEsc (VECTOR-II) ->
  Root -> [hypothetical: Credential Access -> Lateral Movement -> Database]

Every node carries its own risk score (from the Risk Engine), every
edge carries its own MITRE technique and CVE. Output in two formats:
  1. Mermaid diagram (renders automatically on GitHub)
  2. JSON graph (node/edge list - portable to other tools, e.g.
     Neo4j, Gephi, or a web-based graph visualizer)

NOTE: the "Credential Access -> Lateral Movement -> Database" segment
was NOT actually exploited in this lab (the VECTOR-I/II chain ends at
root). This segment is marked as hypothetical/projected with a
distinct node type (HYPOTHETICAL) — to keep what's real and what's
hypothetical from being conflated.
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


@dataclass
class GraphNode:
    node_id: str
    label: str
    node_type: str          # "asset" | "compromise_state" | "hypothetical"
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    evidence: str = ""       # evidence supporting this node's reality


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str
    mitre_technique: Optional[str] = None
    cve: Optional[str] = None
    confirmed: bool = True    # False = hypothetical/projected step


def load_risk_scores() -> dict:
    path = os.path.join(BASE_DIR, "risk-engine", "output", "risk_scores.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        scores = json.load(f)
    return {s["cve"]: s for s in scores}


def build_graph() -> tuple:
    """
    Builds OBSIDIAN PROTOCOL's real attack chain, plus a hypothetical
    extension segment, as a single graph.
    """
    risk_scores = load_risk_scores()

    def risk_for(cve: str) -> tuple:
        s = risk_scores.get(cve)
        if s:
            return s["composite_score"], s["risk_band"]
        return None, None

    r1_score, r1_band = risk_for("CVE-2021-42013")
    r2_score, r2_band = risk_for("CVE-2021-4034")

    nodes = [
        GraphNode("internet", "Internet", "asset",
                   evidence="Starting point of the attack - external network"),
        GraphNode("target49", "TARGET-49 (Apache 2.4.49)", "asset",
                   risk_score=r1_score, risk_band=r1_band,
                   evidence="docker/target-49/Dockerfile - the real image"),
        GraphNode("shell", "labuser shell (foothold)", "compromise_state",
                   evidence="docs/walkthrough.md Stage 4 - shell obtained via RCE"),
        GraphNode("root", "root (TARGET-49)", "compromise_state",
                   risk_score=r2_score, risk_band=r2_band,
                   evidence="docs/walkthrough.md Stage 6 - confirmed via PwnKit"),
        # --- Everything below is HYPOTHETICAL: not exploited in this lab ---
        GraphNode("creddump", "Credential Dump (hypothetical)", "hypothetical",
                   evidence="NOT ACTUALLY EXPLOITED - projection"),
        GraphNode("lateral", "Lateral Movement (hypothetical)", "hypothetical",
                   evidence="NOT ACTUALLY EXPLOITED - projection"),
        GraphNode("database", "Database (hypothetical target)", "hypothetical",
                   evidence="NOT ACTUALLY EXPLOITED - projection, illustrative 'end target'"),
    ]

    edges = [
        GraphEdge("internet", "target49", "VECTOR-I: Path Traversal + RCE",
                   mitre_technique="T1190", cve="CVE-2021-41773", confirmed=True),
        GraphEdge("target49", "shell", "Command execution via CGI redirection",
                   mitre_technique="T1059", cve="CVE-2021-42013", confirmed=True),
        GraphEdge("shell", "root", "VECTOR-II: PwnKit local privesc",
                   mitre_technique="T1548.001", cve="CVE-2021-4034", confirmed=True),
        # Hypothetical segment - marked confirmed=False
        GraphEdge("root", "creddump", "(hypothetical) /etc/shadow or memory dump",
                   mitre_technique="T1003", confirmed=False),
        GraphEdge("creddump", "lateral", "(hypothetical) SSH using a stolen credential",
                   mitre_technique="T1021", confirmed=False),
        GraphEdge("lateral", "database", "(hypothetical) access to the DB server",
                   mitre_technique="T1213", confirmed=False),
    ]

    return nodes, edges


def render_mermaid(nodes: list, edges: list) -> str:
    lines = ["graph LR"]

    style_map = {"asset": "fill:#16213e,stroke:#0f3460,color:#fff",
                 "compromise_state": "fill:#7a1f2b,stroke:#e94560,color:#fff",
                 "hypothetical": "fill:#2a2a2a,stroke:#888,color:#aaa,stroke-dasharray: 5 5"}

    for n in nodes:
        risk_label = f"<br/>Risk: {n.risk_score}/100 ({n.risk_band})" if n.risk_score else ""
        hyp_label = "<br/>(HYPOTHETICAL)" if n.node_type == "hypothetical" else ""
        lines.append(f'    {n.node_id}["{n.label}{risk_label}{hyp_label}"]')

    for e in edges:
        style = "-.->" if not e.confirmed else "-->"
        cve_part = f" {e.cve}" if e.cve else ""
        lines.append(f'    {e.source} {style}|"{e.label}{cve_part}<br/>{e.mitre_technique}"| {e.target}')

    for n in nodes:
        lines.append(f"    style {n.node_id} {style_map[n.node_type]}")

    return "\n".join(lines)


def print_text_graph(nodes: list, edges: list):
    node_map = {n.node_id: n for n in nodes}
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — RISK GRAPH (Attack Path)")
    print("=" * 70)
    print()
    for e in edges:
        src, tgt = node_map[e.source], node_map[e.target]
        marker = "──>" if e.confirmed else "··> (HYPOTHETICAL)"
        risk_str = f" [Risk: {tgt.risk_score}/100, {tgt.risk_band}]" if tgt.risk_score else ""
        print(f"  {src.label}")
        print(f"    {marker}  {e.label}  ({e.mitre_technique}{', ' + e.cve if e.cve else ''})")
        print(f"  {tgt.label}{risk_str}")
        print()


def main():
    nodes, edges = build_graph()
    print_text_graph(nodes, edges)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    graph_json = {
        "nodes": [asdict(n) for n in nodes],
        "edges": [asdict(e) for e in edges],
    }
    json_path = os.path.join(OUTPUT_DIR, "risk_graph.json")
    with open(json_path, "w") as f:
        json.dump(graph_json, f, indent=2, ensure_ascii=False)

    mermaid_path = os.path.join(BASE_DIR, "docs", "risk-graph.mermaid")
    with open(mermaid_path, "w") as f:
        f.write(render_mermaid(nodes, edges))

    print(f"[+] JSON graph: {json_path}")
    print(f"[+] Mermaid diagram: {mermaid_path}")


if __name__ == "__main__":
    main()
