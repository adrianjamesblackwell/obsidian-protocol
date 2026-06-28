#!/usr/bin/env python3
"""
reporting/executive/executive_report.py

OBSIDIAN PROTOCOL — Executive Report Generator

REAL-WORLD PROBLEM: A CEO/board does not read a Sigma rule, a MITRE
technique ID, or a CVSS vector string. But they read a 6-8 line
summary like "Risk Level: HIGH", "Assets Affected: 2", "Patch
Required: Yes" and make a decision.

SOLUTION: This engine distills the output of ALL sub-modules into a
SINGLE-PAGE executive summary. No technical detail — only the minimum,
accurate information needed to make a decision.
"""

import json
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")


@dataclass
class ExecutiveSummary:
    generated_at: str
    risk_level: str
    risk_score: float
    assets_affected: int
    detection_coverage_pct: float
    patch_required: bool
    estimated_impact: str
    top_recommendations: list = field(default_factory=list)
    incidents_summary: str = ""


def safe_load(path: str):
    full = os.path.join(BASE_DIR, path)
    if not os.path.exists(full):
        return None
    with open(full) as f:
        return json.load(f)


def determine_risk_level(risk_scores: list) -> tuple:
    if not risk_scores:
        return ("UNKNOWN", 0.0)
    max_score = max(s["composite_score"] for s in risk_scores)
    band = next(s["risk_band"] for s in risk_scores if s["composite_score"] == max_score)
    return (band, max_score)


def determine_impact(risk_level: str, coverage_pct: float) -> str:
    if risk_level in ("CRITICAL", "HIGH") and coverage_pct < 50:
        return "High - Attack surface is high-risk AND detection capacity is insufficient"
    if risk_level in ("CRITICAL", "HIGH"):
        return "Medium-High - Attack surface is risky but detection capacity exists"
    return "Medium - Standard prioritization is sufficient"


def build_recommendations(root_cause_data: list, telemetry_gap_data: dict) -> list:
    recs = []
    if root_cause_data:
        for r in root_cause_data[:2]:
            if r.get("preventive_actions"):
                recs.append(r["preventive_actions"][0])
    if telemetry_gap_data and telemetry_gap_data.get("recommendations"):
        recs.append(telemetry_gap_data["recommendations"][0])
    return recs[:3] if recs else ["See the detailed technical report: reports/obsidian_protocol_report.pdf"]


def generate_executive_summary() -> ExecutiveSummary:
    risk_scores = safe_load("risk-engine/output/risk_scores.json") or []
    coverage_results = safe_load("purple-team/output/coverage_results.json") or []
    incidents = safe_load("correlation-engine/output/correlated_incidents.json") or []
    root_cause_data = safe_load("root-cause/output/root_cause_report.json") or []
    telemetry_gap_data = safe_load("telemetry-gap/output/telemetry_gap.json")

    risk_level, risk_score = determine_risk_level(risk_scores)

    total_steps = len(coverage_results)
    detected = sum(1 for r in coverage_results if r.get("detected"))
    coverage_pct = round(detected / total_steps * 100, 1) if total_steps else 0.0

    assets_affected = 1

    impact = determine_impact(risk_level, coverage_pct)
    recommendations = build_recommendations(root_cause_data, telemetry_gap_data)

    critical_incidents = [i for i in incidents if i.get("severity") in ("CRITICAL", "HIGH")]
    incidents_summary = (
        f"{len(incidents)} separate events were correlated into {len(critical_incidents)} "
        f"critical/high-severity incident(s)." if incidents else "Correlation data has not been generated yet."
    )

    return ExecutiveSummary(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        risk_level=risk_level,
        risk_score=risk_score,
        assets_affected=assets_affected,
        detection_coverage_pct=coverage_pct,
        patch_required=True,
        estimated_impact=impact,
        top_recommendations=recommendations,
        incidents_summary=incidents_summary,
    )


def print_executive_summary(summary: ExecutiveSummary):
    print("=" * 50)
    print("  OBSIDIAN PROTOCOL — EXECUTIVE SUMMARY")
    print("=" * 50)
    print(f"  Generated At:           {summary.generated_at}")
    print(f"  Risk Level:             {summary.risk_level}  ({summary.risk_score}/100)")
    print(f"  Assets Affected:        {summary.assets_affected}")
    print(f"  Detection Coverage:     {summary.detection_coverage_pct}%")
    print(f"  Patch Required:         {'Yes' if summary.patch_required else 'No'}")
    print(f"  Estimated Impact:       {summary.estimated_impact}")
    print(f"  Incident Summary:       {summary.incidents_summary}")
    print()
    print("  Recommendations:")
    for i, rec in enumerate(summary.top_recommendations, 1):
        print(f"    {i}. {rec}")
    print("=" * 50)


def build_markdown(summary: ExecutiveSummary) -> str:
    lines = [
        "# OBSIDIAN PROTOCOL — Executive Summary",
        "",
        f"**Generated At:** {summary.generated_at}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Risk Level | **{summary.risk_level}** ({summary.risk_score}/100) |",
        f"| Assets Affected | {summary.assets_affected} |",
        f"| Detection Coverage | {summary.detection_coverage_pct}% |",
        f"| Patch Required | {'Yes' if summary.patch_required else 'No'} |",
        f"| Estimated Impact | {summary.estimated_impact} |",
        "",
        f"**Summary:** {summary.incidents_summary}",
        "",
        "## Recommendations",
        "",
    ]
    for i, rec in enumerate(summary.top_recommendations, 1):
        lines.append(f"{i}. {rec}")
    lines.append("")
    lines.append("> For technical details: `reports/obsidian_protocol_report.pdf`")
    return "\n".join(lines)


def main():
    summary = generate_executive_summary()
    print_executive_summary(summary)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    json_path = os.path.join(OUTPUT_DIR, "executive_summary.json")
    with open(json_path, "w") as f:
        json.dump(asdict(summary), f, indent=2, ensure_ascii=False)

    md_path = os.path.join(OUTPUT_DIR, "executive_summary.md")
    with open(md_path, "w") as f:
        f.write(build_markdown(summary))

    print(f"\n[+] JSON: {json_path}")
    print(f"[+] Markdown: {md_path}")


if __name__ == "__main__":
    main()
