# CORRELATION ENGINE
### OBSIDIAN PROTOCOL / Solving Alert Fatigue

## Problem

SOC teams see 20,000–200,000+ alerts a day; a large share get closed
without proper triage, or handled one at a time with no context. The
real problem is usually not "false alarms" — it's that **alerts can't
be tied to each other**: an Apache exploit + sudo + curl + bash +
systemd can look like 5 unrelated alerts, when they're actually the
steps of one attack operation.

## Solution

`correlate.py` groups the raw events in
`telemetry/output/unified_timeline.ndjson` along three dimensions:

1. **Actor identity** — src_ip (network events) or user (host events)
2. **Time window** — default 300s, are these part of the same operation
3. **Causal chain** — does the observed MITRE technique sequence match
   a known kill-chain pattern (`KNOWN_CHAIN_PATTERNS`)

Output: M "Correlated Incidents" instead of N raw events (M ≪ N), each
with its own **confidence score**.

## Usage

```bash
python3 correlation-engine/correlate.py [window_seconds]
```

## Confidence scoring logic

| Case | Score | Meaning |
|---|---|---|
| Exact kill-chain match | 95% | Observed MITRE technique sequence matches a known pattern exactly |
| Partial match | 70% | Observed techniques are a subset of a known pattern |
| Multiple techniques, unrecognized sequence | 40% | More than one technique, but doesn't fit any known chain |
| Single technique | 20% | No chain to evaluate, an isolated signal |

## Known limitation

`KNOWN_CHAIN_PATTERNS` currently only knows this project's own
VECTOR-I/II chain. In a real production system this list could be
derived automatically from MITRE ATT&CK's official campaign/group
dataset (the known TTP sequences of real APT groups) — added to the
Future Work list in `docs/research-findings.md`.

This is the reference implementation. See
[`blackwell-core/correlation-bca/README.md`](../blackwell-core/correlation-bca/README.md)
for the formally specified, Evidence-Graph-native successor (BCA
v1.0) built on top of this same idea.
