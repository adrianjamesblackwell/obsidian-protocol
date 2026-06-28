# EXAMPLES
### OBSIDIAN PROTOCOL / Sample Output

This folder contains sample output so anyone cloning the project can
see what the system actually produces **without running anything**.

> **Important:** these files were not produced by a real operation —
> they were generated from the sample/test data used during
> development (see `purple-team/attack_log_template.json` and
> `telemetry/sample-data/`). When you run your own operation, the
> real modules (`telemetry/`, `purple-team/`, `risk-engine/`,
> `intel-export/`, `reporting/`) produce fresh data into their own
> `output/` folders — these samples are reference only, and are
> deliberately committed rather than excluded by `.gitignore`.

## Contents

| File | Producing module | Description |
|---|---|---|
| `sample_report.html` | reporting/ | Tabbed HTML operation dashboard (7 tabs: Overview, Findings, Detection, Risk & Intel, Engineering, Root Cause, Artifacts) |
| `sample_report.pdf` | reporting/ | PDF operation report (multi-page) |
| `sample_executive_summary.md` | reporting/executive/ | CEO-level executive summary |
| `sample_navigator_layer.json` | reporting/navigator/ | ATT&CK Navigator layer (uploadable to mitre-attack.github.io/attack-navigator) |
| `sample_detection-coverage-matrix.md` | reporting/navigator/ | Markdown coverage matrix |
| `sample_stix_bundle.json` | intel-export/ | STIX 2.1 IOC bundle |
| `sample_correlated_incidents.json` | correlation-engine/ | Alert Fatigue solution: raw events -> incidents |
| `sample_risk_graph.json` / `.mermaid` | risk-graph/ | Internet -> Database attack path graph |

## Quick preview

```bash
# Open the HTML dashboard in a browser
open examples/sample_report.html      # macOS
xdg-open examples/sample_report.html  # Linux
```

The HTML report is a single self-contained file (no external
dependencies) with a sticky tab bar at the top — click through
Overview, Findings, Detection, Risk & Intel, Engineering, Root Cause,
and Artifacts to see each part of the platform's output without
scrolling through one long page.

The Overview tab includes a live, fully interactive render of the
actual Blackwell Evidence Graph: drag any node to reposition it,
scroll to zoom, hover for a real tooltip (kind, weight, provenance),
and click a node to jump straight to the tab and exact row/card it
corresponds to — an ASSERTION node opens its Decision Engine card in
Findings, an INDICATOR node opens its CVE row in Risk & Intel. Every
other chart in the report (the risk-distribution donut, the
confidence-vs-priority scatter plot, the MITRE coverage heatmap, the
attack timeline, and IOC decay sparklines) shares the same hover
tooltip and click-to-navigate behavior, all driven directly from the
underlying JSON data — nothing is a static image or a decorative
animation.

```bash
# Inspect the Navigator layer visually:
# go to https://mitre-attack.github.io/attack-navigator/
# "Open Existing Layer" -> "Upload from local" -> select sample_navigator_layer.json
```
