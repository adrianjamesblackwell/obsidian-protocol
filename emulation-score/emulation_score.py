#!/usr/bin/env python3
"""
emulation-score/emulation_score.py

OBSIDIAN PROTOCOL — Adversary Emulation Quality Score

REAL-WORLD PROBLEM: Most organizations run Red Team / adversary
emulation operations but never measure the operation's QUALITY.
"We ran a Red Team exercise" is not the same claim as "we ran a good
Red Team exercise."

SOLUTION: this engine uses Correlation Engine + Purple Team output to
produce an emulation quality score across four dimensions:

  1. Attack Diversity   - how many distinct MITRE techniques were used
  2. Coverage            - how much of the MITRE matrix those techniques span
  3. Noise               - how "quiet"/focused the operation stayed
  4. Detection Success   - how much of the operation WARDEN actually caught
"""

import json
import os
from dataclasses import dataclass, asdict

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

MITRE_TOTAL_TECHNIQUES = 216  # MITRE ATT&CK Enterprise v18 reference count


@dataclass
class EmulationScoreResult:
    attack_diversity_pct: float
    coverage_pct: float
    noise_level: str
    noise_score: float
    detection_success_pct: float
    overall_grade: str
    rationale: dict


def load_correlated_incidents() -> list:
    path = os.path.join(BASE_DIR, "correlation-engine", "output", "correlated_incidents.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def load_coverage_results() -> list:
    path = os.path.join(BASE_DIR, "purple-team", "output", "coverage_results.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def compute_attack_diversity(incidents: list) -> tuple:
    all_techniques = set()
    for inc in incidents:
        all_techniques.update(inc.get("mitre_chain", []))

    known_technique_count = 7
    diversity_pct = min(100, len(all_techniques) / known_technique_count * 100) if known_technique_count else 0
    return diversity_pct, len(all_techniques)


def compute_coverage(incidents: list) -> float:
    all_techniques = set()
    for inc in incidents:
        all_techniques.update(inc.get("mitre_chain", []))
    return round(len(all_techniques) / MITRE_TOTAL_TECHNIQUES * 100, 2)


def compute_noise_level(incidents: list) -> tuple:
    """
    Fewer, but high-confidence incidents = a focused, well-run emulation.
    Many, scattered, low-confidence incidents = noisy/amateur.
    """
    if not incidents:
        return ("UNKNOWN", 0.0)

    high_confidence_count = sum(1 for i in incidents if i.get("confidence", 0) >= 70)
    total = len(incidents)
    focus_ratio = high_confidence_count / total if total else 0

    if focus_ratio >= 0.7:
        return ("Low", 90.0)
    if focus_ratio >= 0.4:
        return ("Medium", 60.0)
    return ("High", 30.0)


def compute_detection_success(coverage_results: list) -> float:
    if not coverage_results:
        return 0.0
    detected = sum(1 for r in coverage_results if r.get("detected"))
    return round(detected / len(coverage_results) * 100, 1)


def overall_grade(diversity: float, coverage: float, noise_score: float, detection: float) -> str:
    avg = (diversity + coverage * 2 + noise_score) / 3
    if avg >= 75:
        return "A (High-quality emulation)"
    if avg >= 50:
        return "B (Moderate quality, room to improve)"
    if avg >= 25:
        return "C (Low diversity/realism)"
    return "D (Emulation quality insufficient)"


def main():
    incidents = load_correlated_incidents()
    coverage_results = load_coverage_results()

    if not incidents:
        print("[!] Correlation Engine output not found.")
        print("[!] Run first: python3 correlation-engine/correlate.py")
        return

    diversity_pct, unique_technique_count = compute_attack_diversity(incidents)
    coverage_pct = compute_coverage(incidents)
    noise_level, noise_score = compute_noise_level(incidents)
    detection_pct = compute_detection_success(coverage_results)
    grade = overall_grade(diversity_pct, coverage_pct, noise_score, detection_pct)

    result = EmulationScoreResult(
        attack_diversity_pct=round(diversity_pct, 1),
        coverage_pct=coverage_pct,
        noise_level=noise_level,
        noise_score=noise_score,
        detection_success_pct=detection_pct,
        overall_grade=grade,
        rationale={
            "unique_techniques_used": unique_technique_count,
            "total_incidents": len(incidents),
            "mitre_total_techniques_reference": MITRE_TOTAL_TECHNIQUES,
            "note": "coverage_pct is computed over MITRE's FULL 216 techniques - "
                    "expected to come out low given this project's scope (2 CVEs), "
                    "and that is normal, not a bug.",
        },
    )

    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — ADVERSARY EMULATION QUALITY SCORE")
    print("=" * 70)
    print(f"\n  Attack Diversity:     {result.attack_diversity_pct}%  "
          f"({unique_technique_count} unique technique(s), over this project's known technique set)")
    print(f"  MITRE Matrix Coverage: {result.coverage_pct}%  (over all 216 techniques - low is expected)")
    print(f"  Noise Level:           {result.noise_level}  (score: {result.noise_score}/100, lower noise = better)")
    print(f"  Detection Success:     {result.detection_success_pct}%  (WARDEN's catch rate for this emulation)")
    print(f"\n  OVERALL GRADE: {result.overall_grade}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "emulation_score.json")
    with open(out_path, "w") as f:
        json.dump(asdict(result), f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {out_path}")


if __name__ == "__main__":
    main()
