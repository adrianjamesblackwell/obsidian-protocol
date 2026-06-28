# BLACKWELL EVIDENCE RANKING (BER) v1.0

### "What should an analyst look at first" — a different question from "how much should the system believe this"

## Problem

Confidence (BCE) and triage priority (BER) are easy to conflate, but
they are not the same question, and conflating them produces a bad
default: ranking findings by confidence descending would systematically
push low-confidence-but-high-severity findings to the bottom of the
queue — exactly the cases where human judgment is most needed to
resolve the ambiguity.

## Formula

```
priority(a) = 0.35·severity(a) + 0.20·(1 − confidence(a)) + 0.20·recency(a) + 0.25·blast_radius(a)
```

| Term | Source | Note |
|---|---|---|
| `severity` | Read from BCA/BRS upstream | Not re-derived here |
| `1 − confidence` | **Inverted on purpose** | See below — this is the part of BER easiest to get backwards |
| `recency` | `exp(−age_hours/24)` | Same decay family as `ioc-decay`'s half-life model, applied to finding staleness |
| `blast_radius` | Distinct entity count, via the Knowledge Graph projection | A finding touching 5+ entities ranks above one touching one |

## Why the confidence term is inverted

A high-confidence conclusion is, by definition, one the system is
already fairly sure about — a human re-checking it adds comparatively
little marginal value. A low-confidence, high-severity conclusion is
exactly where human judgment resolves the most ambiguity before a
decision to act. Ranking by raw confidence (high first) would starve
the cases that most need attention. This is stated explicitly because
"rank by confidence, descending" is the intuitive but wrong default a
less careful design would ship without noticing.

## Why this is a separate algorithm from the Confidence Engine

"How much do I believe this" and "how urgently should a human look at
this" can point in opposite directions for the same finding — the
inverted term above is the clearest example. Keeping them as two
separately-inspectable numbers, both visible to the Decision Engine,
makes that tradeoff visible to an analyst instead of burying it inside
one conflated score.

## Usage

```bash
python3 blackwell-core/evidence-ranking/evidence_ranking.py
```

Output: `output/ranked_findings.json`

## Known limitations

1. **Weights are hand-set.** No "analyst actually needed to see this
   first" labeled outcome dataset exists to fit against.
2. **`recency` is computed at scoring time** — this produces a
   point-in-time snapshot, not a live-updating rank. Re-run to refresh.
3. **`blast_radius` via raw entity count is a crude impact proxy.** It
   doesn't distinguish "touches 5 disposable test hosts" from "touches
   5 domain controllers" — there is no asset-criticality data source
   in this lab to weight by, so none is faked. Listed as future work.
