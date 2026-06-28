#!/usr/bin/env python3
"""
reporting/generate_all_reports.py

OBSIDIAN PROTOCOL — Full Operation Chain Orchestrator (v3)

Runs every module in the correct dependency order, in one command:

  Telemetry (assumed already run, with --live or sample-data)
        |
        v
  1. Correlation Engine    (group raw events into incidents)
  2. Purple Team Validate   (attack<->detection matching)   [must also be run manually]
        |
        +--> 3. Risk Engine            (composite risk score)
        +--> 4. Coverage Heatmap        (MITRE-technique-based visual coverage)
        +--> 5. Telemetry Gap Analysis  (which log source is missing)
        +--> 6. Rule Quality Analyzer    (quality of WARDEN rules)
        +--> 7. IOC Decay Engine          (IOC confidence/decay score)
        +--> 8. Root Cause Discovery       (CVE -> root cause chain)
        +--> 9. Emulation Score             (red team quality score)
        |
        v
  10. Risk Graph              (attack path visualization)
  11. Attack Replay            (timeline snapshot)
  12. ATT&CK Navigator Layer    (Coverage Matrix)
  13. Executive Report           (CEO-level summary)
  14. HTML + PDF Operation Report (synthesis of everything above)
        |
        v
  ============= BLACKWELL CORE (reasoning layer) =============
  15. Evidence Graph              (build the substrate from all of the above)
  16. Correlation Algorithm (BCA)  (formalized, graph-native correlation)
  17. Risk Score (BRS)             (formalized, graph-integrated risk scoring)
  18. Confidence Engine             (continuous multi-signal confidence)
  19. Knowledge Graph                (entity-relationship projection)
  20. Temporal Reasoning              (tempo/anomalous-gap analysis)
  21. Evidence Ranking                 (analyst-attention priority)
  22. Attack Path Prediction            (structural next-step hypotheses)
  23. Decision Engine                    (technical + executive briefings)

Note: this script does NOT run telemetry/build_timeline.py or
intel-export/stix_export.py -- those are data-source modules and must
be run separately by the operator (see README.md, "End-to-end run").
This script only runs the downstream analysis/report/reasoning layers
once that data already exists; if data is missing, each module prints
its own "[!] no data" warning and is skipped silently.

Usage:
    python3 reporting/generate_all_reports.py
"""

import subprocess
import sys
import os

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")


def run_step(description: str, script_path: str, args: list = None):
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    cmd = [sys.executable, script_path] + (args or [])
    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode != 0:
        print(f"[!] '{script_path}' failed (exit code {result.returncode}). Continuing...")


def main():
    steps = [
        ("1/23 -- Correlation Engine (Alert Fatigue)", "correlation-engine/correlate.py"),
        ("2/23 -- Risk Scoring Engine", "risk-engine/risk_engine.py"),
        ("3/23 -- Detection Coverage Heatmap", "coverage-heatmap/heatmap.py"),
        ("4/23 -- Telemetry Gap Analysis", "telemetry-gap/gap_analysis.py"),
        ("5/23 -- Rule Quality Analyzer", "rule-quality/analyze_rules.py"),
        ("6/23 -- IOC Decay Engine", "ioc-decay/ioc_decay.py"),
        ("7/23 -- Root Cause Discovery", "root-cause/root_cause.py"),
        ("8/23 -- Adversary Emulation Score", "emulation-score/emulation_score.py"),
        ("9/23 -- Risk Graph (Attack Path)", "risk-graph/risk_graph.py"),
        ("10/23 -- Attack Replay Snapshot", "attack-replay/replay.py"),
        ("11/23 -- ATT&CK Navigator Layer + Coverage Matrix", "reporting/navigator/generate_navigator_layer.py"),
        ("12/23 -- Executive Report (CEO Summary)", "reporting/executive/executive_report.py"),
        ("13/23 -- HTML Operation Report", "reporting/generate_html_report.py"),
        ("14/23 -- PDF Operation Report", "reporting/generate_pdf_report.py"),
        ("15/23 -- Blackwell Evidence Graph (BEG)", "blackwell-core/evidence-graph/evidence_graph.py"),
        ("16/23 -- Blackwell Correlation Algorithm (BCA)", "blackwell-core/correlation-bca/bca.py"),
        ("17/23 -- Blackwell Risk Score (BRS)", "blackwell-core/risk-score-brs/brs.py"),
        ("18/23 -- Blackwell Confidence Engine", "blackwell-core/confidence-engine/confidence_engine.py"),
        ("19/23 -- Blackwell Knowledge Graph", "blackwell-core/knowledge-graph/knowledge_graph.py"),
        ("20/23 -- Blackwell Temporal Reasoning", "blackwell-core/temporal-reasoning/temporal_reasoning.py"),
        ("21/23 -- Blackwell Evidence Ranking", "blackwell-core/evidence-ranking/evidence_ranking.py"),
        ("22/23 -- Blackwell Attack Path Prediction", "blackwell-core/attack-path-prediction/attack_path_prediction.py"),
        ("23/23 -- Blackwell Decision Engine (synthesis)", "blackwell-core/decision-engine/decision_engine.py"),
    ]

    for description, rel_path in steps:
        run_step(description, os.path.join(BASE_DIR, rel_path))

    print(f"\n{'='*60}")
    print("  ALL ANALYSIS AND REPORTS GENERATED")
    print(f"{'='*60}")
    print("  Operation reports:")
    print("    reports/obsidian_protocol_report.html")
    print("    reports/obsidian_protocol_report.pdf")
    print("    reports/executive_summary.md / .json")
    print("  Analysis output:")
    print("    correlation-engine/output/correlated_incidents.json")
    print("    coverage-heatmap/output/ + docs/coverage-heatmap.md")
    print("    telemetry-gap/output/ + docs/telemetry-gap-analysis.md")
    print("    rule-quality/output/rule_quality_report.json")
    print("    ioc-decay/output/ioc_confidence.json")
    print("    root-cause/output/root_cause_report.json")
    print("    emulation-score/output/emulation_score.json")
    print("    risk-graph/output/ + docs/risk-graph.mermaid")
    print("    attack-replay/output/replay_timeline.json")
    print("    reporting/navigator/obsidian_protocol_layer.json")
    print("    docs/detection-coverage-matrix.md")
    print("  Blackwell Core reasoning layer:")
    print("    blackwell-core/evidence-graph/output/evidence_graph.json")
    print("    blackwell-core/decision-engine/output/technical_briefing.md")
    print("    blackwell-core/decision-engine/output/executive_briefing.md")


if __name__ == "__main__":
    main()
