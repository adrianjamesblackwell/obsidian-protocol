# REPORTING
### OBSIDIAN PROTOCOL / Automated Report Generation + ATT&CK Navigator

This module combines the output of every other module (Telemetry,
Purple Team, Risk Engine, SIGINT, WARDEN, Intel Export) and produces
four different formats.

## One command

```bash
python3 reporting/generate_all_reports.py
```

This produces, in sequence:

1. **ATT&CK Navigator Layer** (`reporting/navigator/obsidian_protocol_layer.json`)
   — in the official MITRE Navigator v4.5 format, can be uploaded
   directly to
   [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).
   Green = caught by WARDEN, Red = detection gap.

2. **Detection Coverage Matrix** (`docs/detection-coverage-matrix.md`)
   — a Markdown table for a quick look without uploading the
   Navigator file.

3. **HTML Report** (`reports/obsidian_protocol_report.html`)
   — self-contained (no external dependencies), dark-themed, opens
   directly in a browser.

4. **PDF Report** (`reports/obsidian_protocol_report.pdf`)
   — a multi-page, shareable formal report generated with reportlab,
   using the DejaVu Sans Unicode font for full character coverage.

## Data flow

```
Purple Team (coverage_results.json) ──┐
Risk Engine (risk_scores.json) ───────┼──> collect_report_data.py ──> HTML + PDF
Telemetry (unified_timeline.ndjson) ──┤
Intel Export (stix bundle) ───────────┘
                │
                └──> generate_navigator_layer.py ──> Navigator JSON + Coverage Matrix
```

`collect_report_data.py` reads all of these files and **does not
silently swallow missing modules** — it states explicitly at the top
of the report which module hasn't been run yet. This removes the risk
of "data is missing but the report looks complete."

## Dependency order

For complete data, the following needs to have run in this order
before generating reports:

```bash
# 1. Threat intel
python3 threat-intel/fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034

# 2. Telemetry
python3 telemetry/build_timeline.py --live

# 3. Purple Team validation
python3 purple-team/validate.py purple-team/my_attack_log.json

# 4. Risk scoring
python3 risk-engine/risk_engine.py

# 5. STIX export
python3 intel-export/stix_export.py

# 6. All reports
python3 reporting/generate_all_reports.py
```

If any step is skipped, the report states this explicitly and
continues with whatever data exists — it doesn't error out, it just
runs quietly with what's available.

## File structure

```
reporting/
├── collect_report_data.py        # Shared layer that collects data from every module
├── generate_html_report.py        # HTML report generator
├── generate_pdf_report.py          # PDF report generator (reportlab + DejaVu Sans)
├── generate_all_reports.py         # One-command orchestrator
├── executive/
│   └── executive_report.py          # CEO-level single-page summary
└── navigator/
    └── generate_navigator_layer.py # ATT&CK Navigator layer + coverage matrix generator
```

This module's output also feeds the
[Blackwell Decision Engine](../blackwell-core/decision-engine/README.md),
which produces a further-synthesized technical and executive briefing
on top of everything generated here.
