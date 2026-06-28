#!/usr/bin/env python3
"""
coverage-heatmap/heatmap.py

OBSIDIAN PROTOCOL — Detection Coverage Heatmap

REAL-WORLD PROBLEM: An organization will often say "we use MITRE
ATT&CK," but nobody can give a precise answer to "of the 14 tactics
and 216 techniques (MITRE Enterprise Matrix v18), how many can we
ACTUALLY detect." That means the question "what can't we see" goes
unanswered — which is exactly the blind spot an attacker benefits from.

SOLUTION: this engine automatically computes which MITRE
tactics/techniques the Sigma/YARA rules in the WARDEN module and the
Purple Team coverage results actually cover, and produces a
tactic-based heatmap.

Data sources:
  - detection/sigma/*.yml  -> technique IDs from the rules' 'tags' field
  - purple-team/output/coverage_results.json -> actually VALIDATED coverage
  - correlation-engine/output/correlated_incidents.json -> observed techniques

Three distinct "coverage" concepts are reported separately (keeping
these distinct is methodologically critical):
  1. RULE COVERAGE: do we have a Sigma/YARA rule for this technique at all?
  2. VALIDATED COVERAGE: did that rule actually catch a real attack
     (Purple Team validation)?
  3. OBSERVED COVERAGE: was this technique ever observed during the operation?

"We have a rule" and "this rule actually works" are DIFFERENT claims
— this engine does not blur that distinction.
"""

import json
import os
import re
import glob
from collections import defaultdict

# MITRE ATT&CK Enterprise Matrix v18: 14 tactics (official order).
# Source: https://attack.mitre.org/tactics/enterprise/
# The total technique count (216) and sub-technique count (475) are
# kept for reference only; this project only shows the tactic
# distribution of the techniques it actually covers, and does NOT
# download MITRE's full STIX dataset to verify a technique's "correct"
# tactic assignment here (see README "Known Limitation").
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
MITRE_TOTAL_TECHNIQUES = 216  # MITRE ATT&CK Enterprise v18

# This project's known technique -> tactic mapping (extensible). In a
# real production system this would be pulled automatically from
# MITRE's official STIX/CTI dataset
# (attack.mitre.org/resources/attack-data-and-tools/) - here it's a
# small, manual reference table.
TECHNIQUE_TO_TACTIC = {
    "T1595": "Reconnaissance",
    "T1190": "Initial Access",
    "T1059": "Execution",
    "T1548.001": "Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1083": "Discovery",
    "T1574": "Persistence",
}

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

BAR_WIDTH = 20


def extract_techniques_from_sigma_rules() -> set:
    """Extracts technique IDs from the 'tags' field in detection/sigma/*.yml files."""
    techniques = set()
    sigma_files = glob.glob(os.path.join(BASE_DIR, "detection", "sigma", "*.yml"))

    for f in sigma_files:
        with open(f) as fh:
            content = fh.read()
        # Regex-extract attack.txxxx / attack.txxxx.xxx patterns under
        # tags: (regex rather than a full YAML parse, since we only
        # need the tags field and this keeps the dependency footprint small)
        matches = re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", content, re.IGNORECASE)
        for m in matches:
            techniques.add(m.upper())
    return techniques


def load_validated_techniques() -> set:
    """Extracts techniques ACTUALLY caught, per Purple Team coverage."""
    path = os.path.join(BASE_DIR, "purple-team", "output", "coverage_results.json")
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        results = json.load(f)
    return {r["mitre_technique"] for r in results if r.get("detected") and r.get("mitre_technique")}


def load_observed_techniques() -> set:
    """Extracts the techniques the Correlation Engine observed during the operation."""
    path = os.path.join(BASE_DIR, "correlation-engine", "output", "correlated_incidents.json")
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        incidents = json.load(f)
    observed = set()
    for inc in incidents:
        observed.update(inc.get("mitre_chain", []))
    return observed


def compute_tactic_coverage(rule_techniques: set, validated_techniques: set, observed_techniques: set) -> dict:
    """
    Computes three separate coverage percentages per tactic. The
    percentage is computed over the techniques known in this
    project's own TECHNIQUE_TO_TACTIC table (not over all 216
    techniques — this distinction is stated explicitly in the report).
    """
    by_tactic = defaultdict(lambda: {"known": 0, "rule": 0, "validated": 0, "observed": 0, "techniques": []})

    for tech, tactic in TECHNIQUE_TO_TACTIC.items():
        by_tactic[tactic]["known"] += 1
        by_tactic[tactic]["techniques"].append(tech)
        if tech in rule_techniques:
            by_tactic[tactic]["rule"] += 1
        if tech in validated_techniques:
            by_tactic[tactic]["validated"] += 1
        if tech in observed_techniques:
            by_tactic[tactic]["observed"] += 1

    result = {}
    for tactic in MITRE_TACTICS:
        data = by_tactic.get(tactic, {"known": 0, "rule": 0, "validated": 0, "observed": 0, "techniques": []})
        known = data["known"]
        result[tactic] = {
            "known_techniques_in_scope": known,
            "rule_coverage_pct": round(data["rule"] / known * 100, 0) if known else 0,
            "validated_coverage_pct": round(data["validated"] / known * 100, 0) if known else 0,
            "observed_coverage_pct": round(data["observed"] / known * 100, 0) if known else 0,
            "techniques": data["techniques"],
        }
    return result


def render_bar(pct: float, width: int = BAR_WIDTH) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


def print_heatmap(coverage: dict):
    print("=" * 78)
    print("  OBSIDIAN PROTOCOL — DETECTION COVERAGE HEATMAP")
    print("=" * 78)
    print(f"\n  MITRE ATT&CK Enterprise v18: {len(MITRE_TACTICS)} tactics, {MITRE_TOTAL_TECHNIQUES} techniques (reference)")
    print(f"  Known techniques covered by this project: {len(TECHNIQUE_TO_TACTIC)}")
    print( "  (Note: percentages are computed over the technique set this project")
    print( "   currently knows about/has labeled, not over MITRE's full 216 techniques.)\n")

    print(f"  {'TACTIC':<22} {'VALIDATED (real)':<32} {'RULE (exists)':<32}")
    print("  " + "-" * 74)
    for tactic in MITRE_TACTICS:
        data = coverage[tactic]
        if data["known_techniques_in_scope"] == 0:
            continue
        v_pct = data["validated_coverage_pct"]
        r_pct = data["rule_coverage_pct"]
        v_bar = render_bar(v_pct)
        r_bar = render_bar(r_pct)
        print(f"  {tactic:<22} {v_bar} {v_pct:>4.0f}%      {r_bar} {r_pct:>4.0f}%")

    print()
    total_known = sum(d["known_techniques_in_scope"] for d in coverage.values())
    total_validated = sum(round(d["validated_coverage_pct"] / 100 * d["known_techniques_in_scope"]) for d in coverage.values())
    total_rule = sum(round(d["rule_coverage_pct"] / 100 * d["known_techniques_in_scope"]) for d in coverage.values())
    print(f"  TOTAL: {total_validated}/{total_known} technique(s) VALIDATED as caught "
          f"({total_validated/total_known*100:.0f}%), {total_rule}/{total_known} have a rule "
          f"({total_rule/total_known*100:.0f}%)")
    print(f"\n  See detection/README.md for the coverage expansion roadmap")


def build_markdown_report(coverage: dict) -> str:
    lines = [
        "# Detection Coverage Heatmap",
        "",
        "> Automatically generated by: `coverage-heatmap/heatmap.py`",
        "",
        f"MITRE ATT&CK Enterprise v18 reference: {len(MITRE_TACTICS)} tactics, "
        f"{MITRE_TOTAL_TECHNIQUES} techniques. Techniques known to this project: "
        f"{len(TECHNIQUE_TO_TACTIC)} (percentages below are over this subset).",
        "",
        "| Tactic | Validated Coverage | Rule Coverage | Known Techniques |",
        "|---|---|---|---|",
    ]
    for tactic in MITRE_TACTICS:
        data = coverage[tactic]
        if data["known_techniques_in_scope"] == 0:
            continue
        lines.append(
            f"| {tactic} | {data['validated_coverage_pct']:.0f}% | "
            f"{data['rule_coverage_pct']:.0f}% | {', '.join(data['techniques'])} |"
        )
    return "\n".join(lines)


def main():
    rule_techniques = extract_techniques_from_sigma_rules()
    validated_techniques = load_validated_techniques()
    observed_techniques = load_observed_techniques()

    coverage = compute_tactic_coverage(rule_techniques, validated_techniques, observed_techniques)
    print_heatmap(coverage)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    json_path = os.path.join(OUTPUT_DIR, "coverage_heatmap.json")
    with open(json_path, "w") as f:
        json.dump(coverage, f, indent=2, ensure_ascii=False)

    md_path = os.path.join(BASE_DIR, "docs", "coverage-heatmap.md")
    with open(md_path, "w") as f:
        f.write(build_markdown_report(coverage))

    print(f"\n[+] JSON: {json_path}")
    print(f"[+] Markdown: {md_path}")


if __name__ == "__main__":
    main()
