#!/usr/bin/env python3
"""
reporting/collect_report_data.py

OBSIDIAN PROTOCOL — Report Data Collector

This module reads the output files produced by every other module
(Telemetry, Purple Team, Risk Engine, SIGINT, WARDEN) and builds the
SINGLE unified context (dict) the HTML/PDF report generators consume.

Missing files are not silently swallowed — which module hasn't been
run is stated explicitly in the report, so the report never risks
"looking complete while quietly missing data."
"""

import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")


def safe_load_json(path: str):
    full_path = os.path.join(BASE_DIR, path)
    if not os.path.exists(full_path):
        return None
    with open(full_path) as f:
        return json.load(f)


def collect_report_context() -> dict:
    coverage_results = safe_load_json("purple-team/output/coverage_results.json")
    risk_scores = safe_load_json("risk-engine/output/risk_scores.json")
    stix_bundle = safe_load_json("intel-export/output/obsidian_protocol_bundle.stix2.json")
    telemetry_path = os.path.join(BASE_DIR, "telemetry/output/unified_timeline.ndjson")

    # --- Newer modules (Correlation, Coverage Heatmap, Telemetry Gap,
    # Rule Quality, IOC Decay, Root Cause, Emulation Score, Risk Graph,
    # Attack Replay) ---
    correlated_incidents = safe_load_json("correlation-engine/output/correlated_incidents.json")
    coverage_heatmap = safe_load_json("coverage-heatmap/output/coverage_heatmap.json")
    telemetry_gap = safe_load_json("telemetry-gap/output/telemetry_gap.json")
    rule_quality = safe_load_json("rule-quality/output/rule_quality_report.json")
    ioc_confidence = safe_load_json("ioc-decay/output/ioc_confidence.json")
    root_cause = safe_load_json("root-cause/output/root_cause_report.json")
    emulation_score = safe_load_json("emulation-score/output/emulation_score.json")
    risk_graph = safe_load_json("risk-graph/output/risk_graph.json")
    attack_replay = safe_load_json("attack-replay/output/replay_timeline.json")

    # --- Blackwell Core reasoning layer ---
    bw_evidence_graph = safe_load_json("blackwell-core/evidence-graph/output/evidence_graph.json")
    bw_bca_incidents = safe_load_json("blackwell-core/correlation-bca/output/bca_incidents.json")
    bw_brs_scores = safe_load_json("blackwell-core/risk-score-brs/output/brs_scores.json")
    bw_confidence = safe_load_json("blackwell-core/confidence-engine/output/confidence_scores.json")
    bw_knowledge_graph = safe_load_json("blackwell-core/knowledge-graph/output/knowledge_graph.json")
    bw_temporal = safe_load_json("blackwell-core/temporal-reasoning/output/temporal_profiles.json")
    bw_ranked = safe_load_json("blackwell-core/evidence-ranking/output/ranked_findings.json")
    bw_attack_paths = safe_load_json("blackwell-core/attack-path-prediction/output/attack_path_predictions.json")
    bw_decisions = safe_load_json("blackwell-core/decision-engine/output/decision_items.json")

    telemetry_events = []
    if os.path.exists(telemetry_path):
        with open(telemetry_path) as f:
            telemetry_events = [json.loads(line) for line in f if line.strip()]

    missing_modules = []
    if coverage_results is None:
        missing_modules.append("Purple Team (purple-team/validate.py has not been run)")
    if risk_scores is None:
        missing_modules.append("Risk Engine (risk-engine/risk_engine.py has not been run)")
    if stix_bundle is None:
        missing_modules.append("STIX Export (intel-export/stix_export.py has not been run)")
    if not telemetry_events:
        missing_modules.append("Telemetry Pipeline (telemetry/build_timeline.py has not been run)")
    if correlated_incidents is None:
        missing_modules.append("Correlation Engine (correlation-engine/correlate.py has not been run)")
    if coverage_heatmap is None:
        missing_modules.append("Coverage Heatmap (coverage-heatmap/heatmap.py has not been run)")
    if telemetry_gap is None:
        missing_modules.append("Telemetry Gap Analysis (telemetry-gap/gap_analysis.py has not been run)")
    if rule_quality is None:
        missing_modules.append("Rule Quality Analyzer (rule-quality/analyze_rules.py has not been run)")
    if ioc_confidence is None:
        missing_modules.append("IOC Decay Engine (ioc-decay/ioc_decay.py has not been run)")
    if root_cause is None:
        missing_modules.append("Root Cause Discovery (root-cause/root_cause.py has not been run)")
    if emulation_score is None:
        missing_modules.append("Emulation Score (emulation-score/emulation_score.py has not been run)")
    if risk_graph is None:
        missing_modules.append("Risk Graph (risk-graph/risk_graph.py has not been run)")
    if attack_replay is None:
        missing_modules.append("Attack Replay (attack-replay/replay.py has not been run)")
    if bw_decisions is None:
        missing_modules.append("Blackwell Decision Engine (blackwell-core/decision-engine/decision_engine.py has not been run)")

    # Summary statistics
    total_steps = len(coverage_results) if coverage_results else 0
    detected_steps = sum(1 for r in coverage_results if r.get("detected")) if coverage_results else 0
    coverage_pct = round(detected_steps / total_steps * 100, 1) if total_steps else None

    avg_latency = None
    if coverage_results:
        latencies = [r["detection_latency_seconds"] for r in coverage_results if r.get("detected")]
        if latencies:
            avg_latency = round(sum(latencies) / len(latencies), 1)

    highest_risk = max(risk_scores, key=lambda s: s["composite_score"]) if risk_scores else None

    # Correlation Engine summary metrics
    correlation_summary = None
    if correlated_incidents is not None and telemetry_events:
        raw_count = len(telemetry_events)
        incident_count = len(correlated_incidents)
        reduction_pct = round((1 - incident_count / raw_count) * 100, 1) if raw_count else None
        correlation_summary = {
            "raw_event_count": raw_count,
            "incident_count": incident_count,
            "reduction_pct": reduction_pct,
        }

    context = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "project_name": "OBSIDIAN PROTOCOL",
        "missing_modules": missing_modules,
        "coverage_results": coverage_results or [],
        "risk_scores": risk_scores or [],
        "telemetry_events": telemetry_events,
        "telemetry_event_count": len(telemetry_events),
        "stix_object_count": len(stix_bundle["objects"]) if stix_bundle else 0,
        "correlated_incidents": correlated_incidents or [],
        "correlation_summary": correlation_summary,
        "coverage_heatmap": coverage_heatmap,
        "telemetry_gap": telemetry_gap,
        "rule_quality": rule_quality or [],
        "ioc_confidence": ioc_confidence or [],
        "root_cause": root_cause or [],
        "emulation_score": emulation_score,
        "risk_graph": risk_graph,
        "attack_replay": attack_replay or [],
        "blackwell": {
            "evidence_graph": bw_evidence_graph,
            "bca_incidents": bw_bca_incidents or [],
            "brs_scores": bw_brs_scores or [],
            "confidence": bw_confidence or [],
            "knowledge_graph": bw_knowledge_graph,
            "temporal": bw_temporal or [],
            "ranked": bw_ranked or [],
            "attack_paths": bw_attack_paths or {},
            "decisions": bw_decisions or [],
        },
        "summary": {
            "total_attack_steps": total_steps,
            "detected_steps": detected_steps,
            "coverage_pct": coverage_pct,
            "avg_detection_latency": avg_latency,
            "highest_risk_cve": highest_risk["cve"] if highest_risk else None,
            "highest_risk_score": highest_risk["composite_score"] if highest_risk else None,
            "highest_risk_band": highest_risk["risk_band"] if highest_risk else None,
        },
    }
    return context


if __name__ == "__main__":
    ctx = collect_report_context()
    print(json.dumps(ctx, indent=2, ensure_ascii=False))
