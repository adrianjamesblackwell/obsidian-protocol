#!/usr/bin/env python3
"""
rule-quality/analyze_rules.py

OBSIDIAN PROTOCOL — Rule Quality Analyzer

REAL-WORLD PROBLEM: Writing a Sigma rule is easy; writing a GOOD Sigma
rule is hard. Many organizations accumulate hundreds of Sigma rules
without ever systematically asking "does this rule produce false
positives," "what's its performance cost," "is anything missing."

SOLUTION: this engine statically analyzes detection/sigma/*.yml files
and, for each rule, computes:
  - False Positive Risk (how complete/specific the falsepositives field is)
  - Performance Cost (how complex the selection logic is)
  - Coverage (how many MITRE techniques are tagged, how many CVE references)
  - Missing Fields (checks required/recommended Sigma fields)
  - Concrete improvement recommendations

This makes the difference between "a Sigma rule EXISTS" and "a Sigma
rule is GOOD" measurable.
"""

import os
import re
import glob
import json
import yaml
from dataclasses import dataclass, field, asdict

SIGMA_DIR = os.path.join(os.path.dirname(__file__), "..", "detection", "sigma")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

REQUIRED_FIELDS = ["title", "id", "status", "description", "logsource", "detection", "level"]
RECOMMENDED_FIELDS = ["references", "author", "date", "falsepositives", "tags"]

EXPENSIVE_PATTERNS = ["contains", "icontains", "re|", "|re"]


@dataclass
class RuleQualityReport:
    rule_file: str
    title: str = ""
    fp_risk_score: int = 0
    fp_risk_rationale: str = ""
    performance_cost_score: int = 0
    performance_cost_rationale: str = ""
    coverage_score: int = 0
    coverage_rationale: str = ""
    missing_fields: list = field(default_factory=list)
    missing_recommended_fields: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


def stars(n: int) -> str:
    n = max(0, min(5, n))
    return "★" * n + "☆" * (5 - n)


def analyze_fp_risk(rule: dict) -> tuple:
    fp_field = rule.get("falsepositives", [])
    if not fp_field:
        return (5, "falsepositives field is empty - FP scenarios were never assessed")

    fp_text = " ".join(fp_field) if isinstance(fp_field, list) else str(fp_field)
    if fp_text.strip().lower() in ("unknown", "none"):
        return (4, "falsepositives is just 'Unknown'/'None' - no real analysis was done")

    word_count = len(fp_text.split())
    if word_count > 15:
        return (2, f"Detailed FP scenarios defined ({word_count} words) - well analyzed")
    return (3, f"Brief FP note present ({word_count} words) - moderate analysis")


def analyze_performance_cost(rule: dict) -> tuple:
    detection_str = yaml.dump(rule.get("detection", {}))
    expensive_count = sum(detection_str.count(p) for p in EXPENSIVE_PATTERNS)
    field_count = len(re.findall(r"^\s+\w+(\|[\w]+)?:", detection_str, re.MULTILINE))

    if expensive_count == 0:
        return (1, f"Only exact matching used, {field_count} field(s) - low cost")
    if expensive_count <= 2:
        return (2, f"{expensive_count} contains/regex pattern(s), {field_count} field(s) - low-moderate cost")
    if expensive_count <= 5:
        return (3, f"{expensive_count} contains/regex pattern(s) - moderate cost, acceptable on most SIEMs")
    return (4, f"{expensive_count} contains/regex pattern(s) - high cost, performance testing recommended at high log volume")


def analyze_coverage(rule: dict) -> tuple:
    tags = rule.get("tags", [])
    technique_count = sum(1 for t in tags if re.match(r"attack\.t\d{4}", str(t), re.IGNORECASE))
    cve_count = sum(1 for t in tags if str(t).startswith("cve."))
    ref_count = len(rule.get("references", []))

    score = min(5, technique_count + (1 if cve_count else 0) + (1 if ref_count else 0))
    return (max(1, score), f"{technique_count} MITRE technique(s), {cve_count} CVE reference(s), {ref_count} external source(s)")


def find_missing_fields(rule: dict) -> tuple:
    missing_required = [f for f in REQUIRED_FIELDS if f not in rule]
    missing_recommended = [f for f in RECOMMENDED_FIELDS if f not in rule]
    return missing_required, missing_recommended


def build_recommendations(report: RuleQualityReport) -> list:
    recs = []
    if report.fp_risk_score >= 4:
        recs.append("Add specific, realistic scenarios to the falsepositives field")
    if report.performance_cost_score >= 4:
        recs.append("Reduce contains/regex usage; try exact matching or a more specific field selection")
    if report.coverage_score <= 2:
        recs.append("Add the relevant MITRE technique IDs and CVE references to the tags field")
    if report.missing_fields:
        recs.append(f"REQUIRED fields are missing: {', '.join(report.missing_fields)}")
    if report.missing_recommended_fields:
        recs.append(f"Recommended fields are missing: {', '.join(report.missing_recommended_fields)}")
    if not recs:
        recs.append("Rule is in good shape, no further recommendations")
    return recs


def analyze_rule_file(filepath: str) -> RuleQualityReport:
    with open(filepath) as f:
        rule = yaml.safe_load(f)

    fp_score, fp_rationale = analyze_fp_risk(rule)
    perf_score, perf_rationale = analyze_performance_cost(rule)
    cov_score, cov_rationale = analyze_coverage(rule)
    missing_req, missing_rec = find_missing_fields(rule)

    report = RuleQualityReport(
        rule_file=os.path.basename(filepath),
        title=rule.get("title", "(untitled)"),
        fp_risk_score=fp_score,
        fp_risk_rationale=fp_rationale,
        performance_cost_score=perf_score,
        performance_cost_rationale=perf_rationale,
        coverage_score=cov_score,
        coverage_rationale=cov_rationale,
        missing_fields=missing_req,
        missing_recommended_fields=missing_rec,
    )
    report.recommendations = build_recommendations(report)
    return report


def print_report(reports: list):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — RULE QUALITY ANALYZER")
    print("=" * 70)
    for r in reports:
        print(f"\n{r.rule_file}")
        print(f"   {r.title}")
        print(f"   False Positive Risk:  {stars(r.fp_risk_score)}  ({r.fp_risk_rationale})")
        print(f"   Performance Cost:      {stars(r.performance_cost_score)}  ({r.performance_cost_rationale})")
        print(f"   Coverage:               {stars(r.coverage_score)}  ({r.coverage_rationale})")
        if r.missing_fields:
            print(f"   Missing (required):    {', '.join(r.missing_fields)}")
        if r.missing_recommended_fields:
            print(f"   Missing (recommended): {', '.join(r.missing_recommended_fields)}")
        print(f"   Recommendations:")
        for rec in r.recommendations:
            print(f"     - {rec}")


def main():
    rule_files = glob.glob(os.path.join(SIGMA_DIR, "*.yml"))
    if not rule_files:
        print(f"[!] No Sigma rules found: {SIGMA_DIR}")
        return

    reports = [analyze_rule_file(f) for f in rule_files]
    print_report(reports)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "rule_quality_report.json")
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in reports], f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {out_path}")


if __name__ == "__main__":
    main()
