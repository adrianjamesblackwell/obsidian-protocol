#!/usr/bin/env python3
"""
risk-engine/risk_engine.py

OBSIDIAN PROTOCOL — Risk Scoring Engine

This module produces a project-specific COMPOSITE RISK SCORE. Instead
of just reading CVSS, it weights and combines four distinct signals:

  1. THREAT             -> CVSS base score (NVD)                  [weight: 0.25]
  2. ACTIVE EXPLOITATION -> In CISA KEV, for how long              [weight: 0.30]
  3. CAMPAIGN BREADTH    -> Known botnets, sector diversity        [weight: 0.20]
  4. DEFENSE GAP         -> The LOWER our Purple Team coverage,
                             the HIGHER the risk (inversely
                             proportional to our own detection
                             coverage)                              [weight: 0.25]

Formula logic: a CVE's CVSS is fixed, but the REAL risk depends on
whether it's being actively exploited (KEV), whether it's part of a
broad campaign (botnet/sector), AND whether our own defense layer
(WARDEN) can catch it. The last factor (#4) is project-specific: it
operationalizes the principle that "this CVE's real risk in our
environment depends on how well we can actually see it."

Score 0-100, four bands: CRITICAL (80-100), HIGH (60-79),
MEDIUM (40-59), LOW (0-39).

Inputs:
  - threat-intel/cve_intel_output.json   (NVD + KEV + campaign data)
  - purple-team/output/coverage_results.json (detection coverage)

Output:
  - risk-engine/output/risk_scores.json
"""

import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Optional

WEIGHTS = {
    "threat_cvss": 0.25,
    "active_exploitation": 0.30,
    "campaign_breadth": 0.20,
    "defense_gap": 0.25,
}

THREAT_INTEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "threat-intel", "cve_intel_output.json"
)
COVERAGE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "purple-team", "output", "coverage_results.json"
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


@dataclass
class RiskScore:
    cve: str
    composite_score: float
    risk_band: str
    components: dict
    rationale: str


def score_threat_cvss(cvss_score: Optional[float]) -> float:
    """Normalizes the CVSS 0-10 scale to 0-100."""
    if cvss_score is None:
        return 50.0  # neutral default if data is missing, rather than silently defaulting to 0
    return min(cvss_score * 10, 100.0)


def score_active_exploitation(kev_data: dict) -> float:
    """
    Reflects both whether this is in KEV AND whether confirmed
    ransomware use has been observed.
    """
    if not kev_data.get("in_kev"):
        return 10.0  # low if not in KEV, but not zero (may simply not be reported yet)

    score = 70.0  # being in KEV alone is a high baseline score
    if kev_data.get("known_ransomware_use") == "Known":
        score += 30.0  # confirmed ransomware use pushes it to the ceiling
    return min(score, 100.0)


def score_campaign_breadth(campaign_data: dict) -> float:
    """
    Produces a "how widely is this CVE being used" score from known
    botnet count and targeted sector diversity.
    """
    botnets = campaign_data.get("known_botnets", [])
    sectors = campaign_data.get("targeted_sectors_2024", [])

    if not botnets and not sectors:
        return 15.0

    score = 30.0
    score += min(len(botnets) * 25, 50)   # +25 per known botnet, capped at 50
    score += min(len(sectors) * 10, 20)    # +10 per sector, capped at 20
    return min(score, 100.0)


def score_defense_gap(coverage_results: list, target_cve: str) -> tuple:
    """
    Looks at Purple Team coverage results: were this CVE's attack
    steps detected? If not (or never tested), the defense gap score
    is HIGH (= higher risk, because our WARDEN layer can't see it).

    Returns tuple: (score, rationale_string)
    """
    relevant = [r for r in coverage_results if r.get("cve") == target_cve]

    if not relevant:
        return (60.0, "Purple Team has not yet been run for this CVE — gap assumed medium-high")

    detected = [r for r in relevant if r.get("detected")]
    coverage_ratio = len(detected) / len(relevant)

    # high coverage ratio (well caught) should mean LOW defense_gap score
    gap_score = (1 - coverage_ratio) * 100

    if detected:
        avg_latency = sum(r.get("detection_latency_seconds", 0) for r in detected) / len(detected)
        if avg_latency > 60:
            gap_score += 10  # caught, but slow — modest risk increase

    gap_score = min(gap_score, 100.0)
    rationale = f"Coverage: {len(detected)}/{len(relevant)} step(s) detected ({coverage_ratio*100:.0f}%)"
    return (gap_score, rationale)


def compute_risk_score(cve: str, nvd_data: dict, kev_data: dict, campaign_data: dict, coverage_results: list) -> RiskScore:
    cvss = nvd_data.get("cvss_v3", {}).get("score") if nvd_data else None

    c_threat = score_threat_cvss(cvss)
    c_exploit = score_active_exploitation(kev_data)
    c_campaign = score_campaign_breadth(campaign_data)
    c_defense, defense_rationale = score_defense_gap(coverage_results, cve)

    composite = (
        c_threat * WEIGHTS["threat_cvss"]
        + c_exploit * WEIGHTS["active_exploitation"]
        + c_campaign * WEIGHTS["campaign_breadth"]
        + c_defense * WEIGHTS["defense_gap"]
    )

    if composite >= 80:
        band = "CRITICAL"
    elif composite >= 60:
        band = "HIGH"
    elif composite >= 40:
        band = "MEDIUM"
    else:
        band = "LOW"

    rationale = (
        f"CVSS={cvss or 'N/A'} (score:{c_threat:.0f}) | "
        f"KEV={'Yes' if kev_data.get('in_kev') else 'No'} (score:{c_exploit:.0f}) | "
        f"Campaign breadth (score:{c_campaign:.0f}) | "
        f"Defense gap (score:{c_defense:.0f}, {defense_rationale})"
    )

    return RiskScore(
        cve=cve,
        composite_score=round(composite, 1),
        risk_band=band,
        components={
            "threat_cvss": round(c_threat, 1),
            "active_exploitation": round(c_exploit, 1),
            "campaign_breadth": round(c_campaign, 1),
            "defense_gap": round(c_defense, 1),
        },
        rationale=rationale,
    )


def run_risk_engine() -> list:
    if not os.path.exists(THREAT_INTEL_PATH):
        print(f"[!] Threat intel data not found: {THREAT_INTEL_PATH}")
        print("[!] Run first: python3 threat-intel/fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034")
        return []

    with open(THREAT_INTEL_PATH) as f:
        intel = json.load(f)

    coverage_results = []
    if os.path.exists(COVERAGE_PATH):
        with open(COVERAGE_PATH) as f:
            coverage_results = json.load(f)
    else:
        print(f"[!] Purple Team coverage data not found, defense_gap will be computed with the default assumption: {COVERAGE_PATH}")

    scores = []
    for cve, data in intel.get("results", {}).items():
        score = compute_risk_score(
            cve=cve,
            nvd_data=data.get("nvd"),
            kev_data=data.get("kev", {}),
            campaign_data=data.get("known_campaigns", {}),
            coverage_results=coverage_results,
        )
        scores.append(score)

    scores.sort(key=lambda s: s.composite_score, reverse=True)
    return scores


def print_risk_report(scores: list):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — RISK SCORING ENGINE REPORT")
    print("=" * 70)
    print(f"\nWeights: Threat(CVSS)={WEIGHTS['threat_cvss']} | "
          f"Active Exploitation(KEV)={WEIGHTS['active_exploitation']} | "
          f"Campaign Breadth={WEIGHTS['campaign_breadth']} | "
          f"Defense Gap={WEIGHTS['defense_gap']}\n")

    for s in scores:
        print(f"[{s.risk_band:8s}] {s.cve}  —  Composite Score: {s.composite_score}/100")
        print(f"    {s.rationale}")
        print()


def export_scores(scores: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump([asdict(s) for s in scores], f, indent=2, ensure_ascii=False)
    print(f"[+] Results saved: {output_path}")


if __name__ == "__main__":
    scores = run_risk_engine()
    if scores:
        print_risk_report(scores)
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        export_scores(scores, os.path.join(OUTPUT_DIR, "risk_scores.json"))
