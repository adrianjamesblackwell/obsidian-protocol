# BLACKWELL VALIDATION FRAMEWORK v1.0

### Three honest validation strategies, and one explicit list of what we do not claim

## The constraint this framework is built around

This project has no access to real comparative data against
commercial SIEM correlation engines (Splunk ES, Microsoft Sentinel,
Elastic Security). No such comparison was run. Reporting one anyway —
even a plausible-sounding estimate — would be fabricated benchmarking,
and a fabricated number is worse than an absent one: it looks like
evidence when it isn't.

Given that constraint, this framework uses three strategies that this
project genuinely *can* measure honestly.

## 1. Synthetic ground-truth precision/recall

[`fixtures/synthetic_events.json`](fixtures/synthetic_events.json) is
a small (10-event), hand-labeled fixture where the correct incident
boundaries are known by construction — not because it resembles
production SOC volume (it doesn't), but because it's the only data
this project can build where the "right answer" is actually known,
which is the precondition for precision/recall to mean anything.

It deliberately exercises three cases:
- **Clean two-actor separation** — two unrelated actors active in the
  same time window must not be merged.
- **A window-boundary straggler** — an event from the same actor,
  placed just outside the 300s window, must be split into a separate
  incident despite sharing an actor.
- **An unmatched-pattern chain** (T1071 → T1041, not in BCA's bundled
  pattern library) — exercises the 0.40-confidence "ambiguous, not
  dismissed" branch honestly, rather than only testing the cases BCA
  is tuned for.

Current result: precision 1.0, recall 1.0, F1 1.0 on this fixture —
reported as a **correctness check on a small adversarial fixture**,
not a production performance claim.

## 2. Ablation study

Runs BCA twice on this project's own real lab telemetry: once with
the real `KNOWN_CHAIN_PATTERNS` library, once with an empty one. This
isolates how much of BCA's behavior comes from temporal/actor grouping
alone versus pattern matching specifically.

The honest finding on the current lab dataset: incident *count* is
identical in both conditions (expected — pattern matching happens
after grouping, so it structurally cannot change boundaries) and mean
confidence was also identical in this particular run, because none of
the current incidents land in the 0.70/0.95 pattern-match branches.
This itself is reported as the finding — the framework does not
manufacture a gap where this run didn't produce one.

## 3. Literature-referenced context table

A small table of *published, cited* industry figures about alert
volume and SOAR/SIEM correlation reduction ratios — presented
explicitly as outside context for interpreting this project's own
numbers, not as a benchmark this project was run against. Every figure
carries its source. None were produced by this project, and the table
says so directly.

## Usage

```bash
python3 blackwell-core/benchmark/run_benchmark.py
```

Output: `output/benchmark_report.json`

## What this framework does not do

- Does not compare BCA's output against any commercial product on the
  same data.
- Does not present the synthetic fixture's precision/recall as a
  production-scale performance claim.
- Does not invent a baseline to beat — "BCA vs. nothing" is reported
  as exactly that, not dressed up as "BCA vs. industry standard."
