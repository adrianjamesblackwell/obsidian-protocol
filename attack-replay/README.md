# ATTACK REPLAY ENGINE
### OBSIDIAN PROTOCOL / Replaying the Operation Step by Step

## Problem

Post-incident reviews are usually static reports. Writing "08:20
recon, 08:28 detection" and actually showing it as a chronological,
step-by-step replay create very different levels of understanding.

## Solution

`replay.py` merges telemetry and Purple Team data and presents the
operation as a time-ordered replay. Each step shows: a timestamp, the
delta since the previous step, an OFFENSIVE/DETECTED/SIGNAL/INFO tag,
and vector/CVE/MITRE metadata.

## Usage

```bash
# Instant mode (print everything immediately)
python3 attack-replay/replay.py

# Live simulation (replay real time gaps at 10x speed)
python3 attack-replay/replay.py --live --speed=10
```

## Known Limitation

`--live` mode simulates real time gaps, but caps the wait at a
maximum of 5 seconds (to avoid waiting indefinitely, since
example/test data can contain gaps of hours or days). With real
operation data — where timestamps are consistent and fall within
minutes of each other — this cap never engages.

## Output Format

Each replayed step (`attack-replay/output/replay_timeline.json`) is a
structured event with the following fields:

| Field | Description |
|---|---|
| `timestamp` | ISO-8601 timestamp of the event |
| `source` | Originating telemetry source (e.g. `apache_access_log`, `auditd`, `ebpf`) |
| `vector` | `VECTOR-I` or `VECTOR-II`, when applicable |
| `cve` | The associated CVE identifier, when applicable |
| `category` | MITRE-aligned category (e.g. `initial_access`) |
| `mitre_technique` | The mapped MITRE ATT&CK technique ID |
| `is_offensive_action` | Whether this event represents an attacker action |
| `is_detection_signal` | Whether this event is itself a detection-relevant signal |
| `detected_by_purple_team` | Whether the Purple Team validation step actually flagged this event |
| `raw_message_preview` | A truncated preview of the original raw log line |

This output feeds directly into `reporting/generate_pdf_report.py`
and `reporting/generate_html_report.py`, so the replay timeline shown
in the final report is generated from the exact same data structure
used for the terminal replay above.
