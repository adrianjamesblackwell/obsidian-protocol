# BLACKWELL TEMPORAL REASONING (BTR) v1.0

### What does the *shape* of an incident's timing tell you, beyond the sequence of techniques?

## Problem

BCA groups events into incidents by time window and matches the
resulting technique sequence against a pattern library. It cannot
distinguish two operationally very different things that produce the
identical technique sequence: an automated exploit chain firing in
seconds, versus a human operator working through the same steps over
minutes with pauses to read output and decide what's next. That
distinction matters for response, and BCA's window+pattern-match alone
doesn't carry it.

## What BTR computes, per incident

| Measure | Definition | What it suggests |
|---|---|---|
| `tempo_class` | Median inter-event gap, bucketed: `MACHINE_SPEED` (<2s), `RAPID` (<30s), `DELIBERATE` (<300s), `SLOW_AND_LOW` (≥300s) | Rough automated-vs-manual signal |
| `regularity` | `1 − coefficient_of_variation(intervals)`, clipped to [0,1] | High = scripted-looking (low variance); low = human-paced |
| `anomalous_gap_indices` | Gaps > 3× the median, flagged | Candidate points where something happened that current telemetry didn't capture |

The thresholds (2s/30s/300s, 3× factor) are stated explicitly as
heuristics chosen by inspecting this project's own lab timing — not
derived from a labeled corpus of attacker behavior. Treat them as a
starting point, not a validated classifier.

## How this feeds back into the Evidence Graph

BTR adds `TEMPORALLY_PRECEDES` edges between consecutive member events
of each incident, with the gap and whether it was flagged anomalous
recorded directly on the edge. This means "is this gap odd" becomes
part of the Evidence Graph itself — queryable by the Decision Engine
— rather than a number that only ever existed in this module's stdout.

## Usage

```bash
python3 blackwell-core/temporal-reasoning/temporal_reasoning.py
```

Output: `output/temporal_profiles.json`, plus an updated Evidence Graph
snapshot.

## Known limitations

1. **Heuristic thresholds**, not derived from labeled data — see
   above.
2. **`regularity()` is noisy at small n.** Short lab chains (2-3
   events) don't give the coefficient-of-variation statistic much to
   work with; the module doesn't suppress or flag this low-n
   unreliability, which a production version should.
3. **Anomalous gaps are statistical outliers, not causal
   explanations.** A flagged gap could mean an operator paused to
   think, a C2 beacon interval, or unrelated activity that happened to
   fall inside the same actor+window grouping. BTR cannot distinguish
   these without more evidence.
