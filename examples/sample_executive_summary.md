# OBSIDIAN PROTOCOL — Executive Summary

**Generated At:** 2026-06-28 18:50 UTC

| Metric | Value |
|---|---|
| Risk Level | **HIGH** (60.5/100) |
| Assets Affected | 1 |
| Detection Coverage | 75.0% |
| Patch Required | Yes |
| Estimated Impact | Medium-High - Attack surface is risky but detection capacity exists |

**Summary:** 3 separate events were correlated into 1 critical/high-severity incident(s).

## Recommendations

1. Automated patch management (e.g. unattended-upgrades + a staging test pipeline)
2. Add 'known bypass techniques' to the regression test matrix for security patches
3. Start collecting 'NetFlow / Network Traffic Metadata' -> closes these blind tactics: Lateral Movement, Command and Control, Exfiltration, Discovery

> For technical details: `reports/obsidian_protocol_report.pdf`