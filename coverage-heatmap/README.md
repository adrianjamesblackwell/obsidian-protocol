# DETECTION COVERAGE HEATMAP
### OBSIDIAN PROTOCOL / Answering "What Can We Actually See?"

## Problem

An organization can say "we use MITRE ATT&CK," yet still be unable to
say how many of the 14 tactics / 216 techniques (MITRE Enterprise
Matrix v18) it can **actually detect**. That blind spot leaves the
question of where defensive investment should go unanswered.

## Three Distinct Coverage Concepts (Not to Be Confused)

| Concept | Question | Source |
|---|---|---|
| **Rule Coverage** | Do we have a Sigma/YARA rule for this technique? | `detection/sigma/*.yml` tags field |
| **Validated Coverage** | Did this rule ACTUALLY catch an attack? | `purple-team/output/coverage_results.json` |
| **Observed Coverage** | Was this technique ever observed during the operation? | `correlation-engine/output/correlated_incidents.json` |

Keeping these three separate is methodologically critical: **"we have
a rule" and "the rule works" are different claims.** A live example
of this in the heatmap output: the Privilege Escalation tactic can
show 100% Rule Coverage (a Sigma rule exists) while Validated Coverage
sits at 0% (the rule didn't fire during the test run, or timing
didn't line up) — that's not a bug, it's a genuine finding the system
surfaces.

## Usage

```bash
python3 coverage-heatmap/heatmap.py
```

Output: an ASCII heatmap in the terminal, a Markdown table in
`docs/coverage-heatmap.md`, and raw data in
`coverage-heatmap/output/coverage_heatmap.json`.

## Known Limitation

The `TECHNIQUE_TO_TACTIC` table currently covers the 7 techniques
this project knows about — it does not download MITRE's full
216-technique STIX dataset and auto-map against it. As a result,
percentages are computed "over the technique subset this project has
labeled," not "over the entirety of MITRE" — the report states this
explicitly rather than hiding it. In a real production system, this
table would be automatically derived from the official STIX bundle at
[attack.mitre.org/resources/attack-data-and-tools](https://attack.mitre.org/resources/attack-data-and-tools/)
(Future Work).
