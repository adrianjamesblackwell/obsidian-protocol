# TELEMETRY GAP ANALYZER
### OBSIDIAN PROTOCOL / Answering "Which Logs Are We Missing?"

## Problem

Organizations know what they monitor, not what they **don't**
monitor. Apache logs exist, DNS logs don't; EDR exists, Sysmon
doesn't. Every missing source creates a blind spot in the MITRE
tactics that source would otherwise cover.

## Solution

`gap_analysis.py` uses a reference table that knows which MITRE
tactics eight common telemetry sources provide visibility into,
checks which of those the project actually collects, and classifies
the result into three categories:

- **Fully visible** — every source covering this tactic is being collected
- **Partially visible** — some sources exist, others are missing
- **Blind** — no source covering this tactic is being collected

## Real Finding (This Project's Own State)

OBSIDIAN PROTOCOL is currently **completely blind in 6 MITRE
tactics**: Collection, Command and Control, Credential Access,
Discovery, Exfiltration, Lateral Movement. This is an expected
outcome — the project focused on the Initial Access/Execution/
Privilege Escalation tactics covered by VECTOR-I/II, and deliberately
left network/EDR-level telemetry out of scope (see
`docs/research-findings.md`, Limitations #8).

## Prioritization Logic

Missing sources are ranked by **how many blind tactics they would
close** — the source that "closes the most blind spots with a single
investment" is recommended first. In this project's own output, that
recommended NetFlow (closing 4 blind tactics) ahead of EDR (3) and DNS
(2).

## Usage

```bash
python3 telemetry-gap/gap_analysis.py
```

## Known Limitation

The `TELEMETRY_SOURCE_COVERAGE` table is manually curated and limited
to eight sources. In a real production system, this would be
automatically derived from MITRE's official "Data Sources" dataset
(which specifies, per technique, which data component is required).
