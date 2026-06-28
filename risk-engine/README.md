# RISK SCORING ENGINE
### OBSIDIAN PROTOCOL / Project-Specific Composite Risk Score

Instead of just reading CVSS, this module applies an original risk
formula that weights and combines **four distinct signals**.

## Formula

```
Composite Score = (CVSS_normalized × 0.25)
                 + (Active_Exploitation × 0.30)
                 + (Campaign_Breadth × 0.20)
                 + (Defense_Gap × 0.25)
```

| Component | Source | Logic |
|---|---|---|
| **Threat (CVSS)** | NVD | Classic severity score, normalized 0-10 → 0-100 |
| **Active Exploitation** | CISA KEV | In KEV? Known ransomware campaign use? |
| **Campaign Breadth** | threat-intel/threat-intelligence.md | Known botnet count + targeted sector diversity |
| **Defense Gap** | **purple-team/output/coverage_results.json** | **How well our own WARDEN module actually catches this CVE** |

## Why this design

The first three components answer "how dangerous is this CVE in the
world" — external, static data. **The fourth component is
project-specific**: it asks "can our own defense layer (Sigma/auditd/
eBPF rules) actually catch this CVE" and gets the answer directly from
the real coverage data the Purple Team module produces.

The practical consequence: **two CVEs with the identical CVSS score
can get different risk scores** — if one is well covered on the
WARDEN side (high coverage → low defense_gap → lower risk), and the
other isn't (no/low coverage → high defense_gap → higher risk). This
operationalizes the principle that "CVSS alone is not a sufficient
prioritization signal — your own observability needs to factor into
the risk calculation" — a small-scale, transparent version of what
real vulnerability management programs do (e.g. models combining KEV +
EPSS + organizational context).

## Usage

The following three steps need to have run, in order:

```bash
# 1. Threat intel data
python3 threat-intel/fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034

# 2. Purple Team coverage data
python3 telemetry/build_timeline.py --live
python3 purple-team/validate.py purple-team/my_attack_log.json

# 3. Compute risk scores
python3 risk-engine/risk_engine.py
```

If step 2 is skipped, the Risk Engine uses a medium-high default value
for the `defense_gap` component under the assumption "not yet tested"
(stated transparently in the rationale field) — rather than silently
producing incorrect data.

## Output

`risk-engine/output/risk_scores.json` — read by the reporting engine
and the ATT&CK Navigator/Coverage Matrix generation.

## Known limitation

The weights (0.25/0.30/0.20/0.25) are fixed and hand-set — not a real
probabilistic model (e.g. the machine-learning-based approach EPSS
uses). This is a deliberate simplification: the goal is a transparent,
explainable score (every component individually visible) rather than
a black-box ML model.

This is the reference implementation. See
[`blackwell-core/risk-score-brs/README.md`](../blackwell-core/risk-score-brs/README.md)
for the formally specified, Evidence-Graph-integrated successor (BRS
v1.0), including a sensitivity analysis of these same weights.
