# RULE QUALITY ANALYZER
### OBSIDIAN PROTOCOL / The Gap Between "We Have a Rule" and "Our Rule Is Good"

## Problem

Writing a Sigma rule is easy; writing a *good* Sigma rule is hard.
Organizations often take pride in "we have X Sigma rules" as a raw
count, without any systematic assessment of those rules' false-
positive risk, performance cost, or missing fields.

## Solution

`analyze_rules.py` statically analyzes the files in
`detection/sigma/*.yml` and produces a score across five dimensions
for each rule:

| Dimension | What It Measures |
|---|---|
| False Positive Risk | How complete and detailed the `falsepositives` field is |
| Performance Cost | The number of `contains`/`regex` patterns used (more costly than exact matches) |
| Coverage | Density of MITRE technique + CVE + external reference metadata |
| Missing Fields | Required/recommended fields from the Sigma specification |
| Recommendations | Concrete improvement suggestions derived from the four dimensions above |

## Usage

```bash
python3 rule-quality/analyze_rules.py
```

## We Tested Our Own Rules With Our Own Tool

This engine was run against the project's own two Sigma rules in the
WARDEN module — the real output is in
`rule-quality/output/rule_quality_report.json`. This practice of
"auditing what we built against our own standard" is a core
quality-assurance principle.

## Known Limitation

The performance cost estimate is a simple heuristic (counting
contains/regex patterns) — a real SIEM's query planner (e.g. Splunk's
search head cost estimation) considers far more complex factors
(index size, time range, field cardinality). This engine provides "an
approximate signal," not a precise benchmark.
