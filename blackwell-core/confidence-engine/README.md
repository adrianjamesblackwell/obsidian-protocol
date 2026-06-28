# BLACKWELL CONFIDENCE ENGINE (BCE) v1.0

### Multi-signal continuous confidence, layered on top of BCA's pattern scoring

## Problem

BCA v1.0 assigns confidence via a four-bucket step function keyed on
pattern-matching alone. Two assertions that both land in the "no
pattern match" bucket get the identical 0.40, even if one is backed
by four independent telemetry sources and the other by one noisy log
line. That's a real loss of information.

## Approach

BCE is a second pass over the Evidence Graph that computes a
continuous confidence score from **four independent signals**, three
positive and one penalty:

```
confidence(a) = clip01( 0.35·corroboration(a)
                       + 0.25·source_diversity(a)
                       + 0.30·pattern_strength(a)
                       - 0.40·contradiction_penalty(a) )
```

| Signal | What it measures | Shape |
|---|---|---|
| `corroboration` | How many SUPPORTS edges point at this node | Saturating: `1 − 1/(1+n)` — diminishing returns on raw count |
| `source_diversity` | How many *distinct* provenances support it | `min(distinct/4, 1.0)` — three sources beat three repeats of one source |
| `pattern_strength` | BCA's own match confidence, rescaled | Re-used, not discarded |
| `contradiction_penalty` | Same saturating shape, on CONTRADICTS edges | Weighted *higher* (0.40) than any single positive term — one credible contradiction can outweigh one corroboration |

This is the standard local-score → global-belief-aggregation pattern
used in evidential reasoning systems generally — we say so directly
rather than presenting graph-level confidence aggregation as if it
were invented here. The contribution is the concrete, inspectable
weighting applied to this specific evidence model.

## Why BCA isn't replaced

BCA only ever sees one actor's event group. BCE sees the whole graph
— other assertions, indicators, and any contradictions that bear on
the same conclusion. BCE incorporates BCA's `pattern_strength` as one
of four signals rather than discarding it.

## Usage

```bash
python3 blackwell-core/confidence-engine/confidence_engine.py
```

Output: `output/confidence_scores.json`

## Known limitations

1. **Weights are hand-set**, same rationale as BRS — no labeled
   outcome dataset exists yet to fit them against.
2. **`source_diversity` trusts provenance strings as a proxy for true
   independence.** Two modules reading the same underlying log stream
   would count as independent even though they aren't. A stricter
   independence model is future work.
3. **Still a hand-engineered function, not learned.** Same
   transparency-over-opacity tradeoff stated in BRS Section 5.
