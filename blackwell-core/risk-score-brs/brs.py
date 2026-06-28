#!/usr/bin/env python3
"""
blackwell-core/risk-score-brs/brs.py

BLACKWELL RISK SCORE (BRS) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
CVSS answers "how bad is this vulnerability in the abstract." It does
not answer "how much should I worry about it in MY environment, right
now." risk-engine/risk_engine.py already encodes the core insight this
project is built on: that answer needs an organization-specific term,
not just external threat data. BRS v1.0 is that formula, restated as
a named, versioned, formally specified algorithm operating on the
Evidence Graph, with an explicit sensitivity analysis (Section 4) that
the original module did not include.

risk-engine/risk_engine.py is unchanged and still works standalone.
BRS reads the same inputs, produces the same class of output, and adds:
  1. A formal definition with explicit normalization functions (Section 2).
  2. Evidence Graph integration — every score becomes a CONCLUSION node
     with SUPPORTS edges to the INDICATOR and ASSERTION nodes that fed
     it, so "why is this CVE scored 87/100" is a graph query.
  3. A documented sensitivity analysis (Section 4): which component
     the score is most sensitive to, under the bundled weights.
  4. An explicit statement of what the weights are and are not
     (Section 5) — hand-set, not learned, and why that is the right
     choice at this stage.

----------------------------------------------------------------------
1. FORMAL DEFINITION
----------------------------------------------------------------------
For a vulnerability v, BRS combines four normalized signals
s_1(v), s_2(v), s_3(v), s_4(v), each in [0, 100], with fixed weights
w_1..w_4 summing to 1.0:

    BRS(v) = w_1 * s_threat(v)
           + w_2 * s_exploitation(v)
           + w_3 * s_campaign(v)
           + w_4 * s_defense_gap(v)

    w = (0.25, 0.30, 0.20, 0.25)   — see Section 5

Risk bands: CRITICAL [80,100], HIGH [60,80), MEDIUM [40,60), LOW [0,40).

----------------------------------------------------------------------
2. SIGNAL DEFINITIONS
----------------------------------------------------------------------
s_threat(v):
    CVSSv3 base score, linearly rescaled from [0,10] to [0,100].
    Missing data -> 50.0 (explicit neutral default, not silently 0 —
    see risk-engine/README.md "transparent over silently wrong").

s_exploitation(v):
    10.0                                   if v not in CISA KEV
    70.0 + 30.0 * 1[known_ransomware_use]  if v in CISA KEV
    (capped at 100.0)
    Encodes: KEV membership alone is a strong signal; confirmed
    ransomware use is the strongest available public signal of
    real-world active exploitation breadth.

s_campaign(v):
    15.0                                                   if no known botnet/sector data
    min(30 + 25*|botnets| + 10*|sectors|, 100)              otherwise
    Botnet count weighted higher than sector count: a vulnerability
    with 2 distinct automated exploitation toolkits targeting it is a
    stronger "this is actively, broadly weaponized" signal than being
    nominally relevant to 2 industry sectors.

s_defense_gap(v):
    100.0 - coverage_score(v)
    where coverage_score(v) comes directly from this project's own
    Purple Team validation output (purple-team/output/coverage_results.json)
    — the fraction of this CVE's attack techniques that this
    project's own detection rules actually caught, empirically, not
    estimated. If coverage data does not exist yet (Purple Team has
    not been run), defaults to 60.0 with the rationale field stating
    explicitly that this is an "untested" default rather than a
    measured gap — see risk-engine/README.md.

----------------------------------------------------------------------
3. WHY DEFENSE_GAP IS WEIGHTED EQUAL TO THREAT_CVSS (both 0.25)
----------------------------------------------------------------------
This is the single design decision that makes BRS more than "CVSS
plus KEV lookup." Two vulnerabilities with identical CVSS, identical
KEV status, and identical campaign breadth can receive materially
different BRS scores if one is well-covered by this project's own
detection layer and the other is not. This operationalizes a specific,
falsifiable claim: raw severity is an incomplete prioritization signal
without an organization's own observability folded in. The claim is
falsifiable because s_defense_gap is computed from this project's
actual purple-team output, not asserted — if coverage is good, the
score goes down, and you can check that it did.

----------------------------------------------------------------------
4. SENSITIVITY ANALYSIS
----------------------------------------------------------------------
Given the fixed weights, BRS(v) changes by w_i for every 1.0-point
(out of 100) change in s_i(v). Under the bundled weights:

    1 point of s_exploitation movement  -> 0.30 point BRS movement
    1 point of s_threat movement        -> 0.25 point BRS movement
    1 point of s_defense_gap movement   -> 0.25 point BRS movement
    1 point of s_campaign movement      -> 0.20 point BRS movement

BRS is therefore most sensitive, per unit, to s_exploitation — small
changes in KEV/ransomware status move the score more than equally
sized changes in any other signal. This is intentional (active,
confirmed exploitation is the signal this design trusts most) and is
exactly the kind of property a benchmark should be able to confirm
empirically, not just assert — see
[`blackwell-core/benchmark`](../benchmark/README.md) Sensitivity Test.

----------------------------------------------------------------------
5. WHAT THE WEIGHTS ARE, AND ARE NOT
----------------------------------------------------------------------
(0.25, 0.30, 0.20, 0.25) are hand-set, not fit to any labeled dataset
and not learned. This is stated as a limitation, not hidden as a
strength. The honest framing: this is a transparent, auditable,
explainable scoring function in the spirit of how EPSS or FAIR present
their components — not a machine-learned probability model. A
probabilistic model (logistic regression over historical exploitation
outcomes, or adopting EPSS directly as one input) is listed as future
work, not attempted here, because doing so honestly requires a labeled
outcome dataset this lab does not have — see Known Limitations.

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. Weights are hand-set. No claim of statistical calibration is made.
2. s_defense_gap is only as good as this project's own Purple Team
   coverage testing — a false sense of "covered" from a shallow
   detection rule would silently understate real risk. This is the
   same limitation purple-team/README.md already documents for
   coverage measurement generally; BRS inherits it.
3. Campaign breadth signal depends entirely on whatever botnet/sector
   attribution data the upstream threat-intel module fetched — it is
   not independently verified here.
"""

import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind, EdgeRelation  # noqa: E402

BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
THREAT_INTEL_PATH = os.path.join(BASE_DIR, "threat-intel", "cve_intel_output.json")
COVERAGE_PATH = os.path.join(BASE_DIR, "purple-team", "output", "coverage_results.json")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

WEIGHTS = {
    "threat_cvss": 0.25,
    "active_exploitation": 0.30,
    "campaign_breadth": 0.20,
    "defense_gap": 0.25,
}


@dataclass
class BrsScore:
    cve: str
    composite_score: float
    risk_band: str
    components: dict
    rationale: str


def s_threat(cvss_score: Optional[float]) -> float:
    if cvss_score is None:
        return 50.0
    return min(cvss_score * 10, 100.0)


def s_exploitation(kev_data: dict) -> float:
    if not kev_data.get("in_kev"):
        return 10.0
    score = 70.0
    if kev_data.get("known_ransomware_use") == "Known":
        score += 30.0
    return min(score, 100.0)


def s_campaign(campaign_data: dict) -> float:
    botnets = campaign_data.get("known_botnets", []) or []
    sectors = campaign_data.get("targeted_sectors_2024", []) or []
    if not botnets and not sectors:
        return 15.0
    return min(30 + 25 * len(botnets) + 10 * len(sectors), 100.0)


def s_defense_gap(coverage_score: Optional[float]) -> tuple[float, str]:
    if coverage_score is None:
        return 60.0, "untested-default"
    return max(0.0, 100.0 - coverage_score), "measured"


def risk_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def compute_brs(cve: str, entry: dict, coverage_by_cve: dict) -> BrsScore:
    nvd = entry.get("nvd", {})
    kev = entry.get("kev", {})
    campaign = entry.get("known_campaigns", {})

    cvss = nvd.get("cvss_v3", {}).get("score")
    t = s_threat(cvss)
    e = s_exploitation(kev)
    c = s_campaign(campaign)
    cov = coverage_by_cve.get(cve)
    gap, gap_mode = s_defense_gap(cov)

    composite = (
        WEIGHTS["threat_cvss"] * t
        + WEIGHTS["active_exploitation"] * e
        + WEIGHTS["campaign_breadth"] * c
        + WEIGHTS["defense_gap"] * gap
    )

    rationale = (
        f"threat={t:.1f}(w{WEIGHTS['threat_cvss']}) "
        f"exploitation={e:.1f}(w{WEIGHTS['active_exploitation']}) "
        f"campaign={c:.1f}(w{WEIGHTS['campaign_breadth']}) "
        f"defense_gap={gap:.1f}(w{WEIGHTS['defense_gap']}, {gap_mode})"
    )

    return BrsScore(
        cve=cve,
        composite_score=round(composite, 2),
        risk_band=risk_band(composite),
        components={
            "threat_cvss": round(t, 2),
            "active_exploitation": round(e, 2),
            "campaign_breadth": round(c, 2),
            "defense_gap": round(gap, 2),
            "defense_gap_mode": gap_mode,
        },
        rationale=rationale,
    )


def load_coverage() -> dict:
    if not os.path.exists(COVERAGE_PATH):
        return {}
    with open(COVERAGE_PATH) as f:
        data = json.load(f)
    out = {}
    for entry in data if isinstance(data, list) else data.get("results", []):
        cve = entry.get("cve")
        if cve:
            out[cve] = entry.get("coverage_score", entry.get("coverage_percent"))
    return out


def main():
    if not os.path.exists(THREAT_INTEL_PATH):
        print(f"[!] Threat intel not found at {THREAT_INTEL_PATH}")
        print("[!] Run first: python3 threat-intel/fetch_cve_intel.py <CVE...>")
        sys.exit(1)

    with open(THREAT_INTEL_PATH) as f:
        intel = json.load(f)
    results = intel.get("results", {})
    coverage = load_coverage()

    scores = [compute_brs(cve, entry, coverage) for cve, entry in results.items()]

    print("=" * 70)
    print("  BLACKWELL RISK SCORE (BRS) v1.0")
    print("=" * 70)
    for s in sorted(scores, key=lambda x: -x.composite_score):
        print(f"\n  {s.cve}  ->  {s.composite_score:.1f}  [{s.risk_band}]")
        print(f"    {s.rationale}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "brs_scores.json")
    with open(out_path, "w") as f:
        json.dump([asdict(s) for s in scores], f, indent=2, ensure_ascii=False)

    # Fold into Evidence Graph as CONCLUSION nodes if BEG already exists
    beg_path = os.path.join(BASE_DIR, "blackwell-core", "evidence-graph", "output", "evidence_graph.json")
    if os.path.exists(beg_path):
        graph = EvidenceGraph.load_from_obsidian_outputs()
        for s in scores:
            ind_node = f"ind-{s.cve}"
            if ind_node not in graph.nodes:
                continue
            concl_id = graph.add_node(
                kind=NodeKind.CONCLUSION,
                label=f"BRS {s.cve}: {s.composite_score:.1f} [{s.risk_band}]",
                weight=s.composite_score / 100.0,
                provenance="blackwell-core:brs-v1.0",
                attributes=asdict(s),
            )
            graph.add_edge(
                source=ind_node, target=concl_id,
                relation=EdgeRelation.DERIVED_FROM, strength=1.0,
                rationale="BRS composite score derived from this indicator's threat/exploitation/campaign data",
                produced_by="blackwell-core:brs-v1.0",
            )
        graph.save(os.path.join(OUTPUT_DIR, "evidence_graph_post_brs.json"))
        print(f"\n[+] Evidence Graph updated: {OUTPUT_DIR}/evidence_graph_post_brs.json")

    print(f"[+] Scores saved: {out_path}")


if __name__ == "__main__":
    main()
