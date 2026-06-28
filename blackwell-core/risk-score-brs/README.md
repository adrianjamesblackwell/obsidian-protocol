# BLACKWELL RISK SCORE (BRS) v1.0

### Formalized, named version of the composite risk formula in `risk-engine/`

## What changed from the legacy risk engine

`risk-engine/risk_engine.py` already contains this project's core
insight: CVSS alone is an incomplete prioritization signal, and an
organization's own detection coverage needs to be a scoring component,
not an afterthought. BRS v1.0 keeps that formula and adds:

1. **Explicit normalization functions** for every signal (module
   docstring, Section 2) instead of logic embedded in conditionals.
2. **Evidence Graph integration.** Every BRS score becomes a
   `CONCLUSION` node in the Blackwell Evidence Graph with a
   `DERIVED_FROM` edge back to its source `INDICATOR` node — "why is
   this CVE scored 75.5" is a graph query, not a re-read of the source
   code.
3. **A sensitivity analysis** (Section 4): under the bundled weights,
   BRS moves 0.30 points per point of exploitation-signal movement,
   0.25 per threat or defense-gap point, 0.20 per campaign point. This
   is checked empirically in
   [`blackwell-core/benchmark`](../benchmark/README.md), not just
   asserted.
4. **An explicit statement of what the weights are** (Section 5):
   hand-set, not fit to a labeled dataset, framed honestly as an
   auditable scoring function rather than a calibrated probability
   model.

## Formula

```
BRS(v) = 0.25 · threat_cvss(v)
       + 0.30 · active_exploitation(v)
       + 0.20 · campaign_breadth(v)
       + 0.25 · defense_gap(v)
```

All four signals normalized to [0,100]. Bands: CRITICAL [80,100],
HIGH [60,80), MEDIUM [40,60), LOW [0,40).

| Signal | Source | What it captures |
|---|---|---|
| `threat_cvss` | NVD | Classic severity, rescaled |
| `active_exploitation` | CISA KEV | In KEV? Confirmed ransomware use? |
| `campaign_breadth` | threat-intel | Known botnets + sector diversity |
| `defense_gap` | **This project's own Purple Team output** | `100 − coverage`. The organization-specific term. |

## Why `defense_gap` is weighted equal to `threat_cvss`

This is the design decision that makes BRS more than a CVSS+KEV
lookup. Two CVEs with identical external severity can land in
different risk bands if one is well-covered by this project's own
detection rules and the other isn't — and that's checkable: the
`defense_gap` component comes from real, measured Purple Team
coverage output, not an assumption.

## Usage

```bash
python3 threat-intel/fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034
python3 blackwell-core/risk-score-brs/brs.py
```

Output: `output/brs_scores.json`, plus an updated Evidence Graph
snapshot if `evidence-graph/output/evidence_graph.json` already exists.

## Known limitations

1. **Weights are hand-set, not learned.** No statistical calibration
   is claimed. A logistic/EPSS-style model is future work, contingent
   on having a labeled outcome dataset this lab does not have.
2. **`defense_gap` inherits Purple Team's own limitations** — a
   shallow detection rule that technically "fires" will understate
   real risk. See `purple-team/README.md`.
3. **Campaign breadth depends on upstream attribution data** fetched
   by `threat-intel/`, not independently verified here.
