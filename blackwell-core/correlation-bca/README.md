# BLACKWELL CORRELATION ALGORITHM (BCA) v1.0

### Named, versioned, formally-specified successor to `correlation-engine/correlate.py`

## What changed from the legacy correlation engine

`correlation-engine/correlate.py` (still present, still works
standalone) groups raw telemetry events into incidents by actor +
time window + kill-chain pattern matching. BCA v1.0 is the same idea,
formalized:

1. **Formal problem statement** instead of an implicit one — see the
   module docstring, Section 1. Stated precisely: this is single-link
   temporal clustering by actor key, composed with sequence-pattern
   confidence scoring. We say this explicitly because it also states
   what BCA does *not* do (see Limitations).
2. **Operates on the Blackwell Evidence Graph**, not a flat JSON list.
   Every incident BCA finds becomes an `ASSERTION` node with
   `SUPPORTS` edges back to the raw events that produced it — queryable
   and auditable, not a side file you have to cross-reference by hand.
3. **An explicit, documented scoring function** (Section 3) instead of
   the same logic spread across nested conditionals.
4. **A stated evaluation protocol** (Section 5) — see
   [`blackwell-core/benchmark`](../benchmark/README.md) for the actual
   numbers this produces on this project's own data, and for what we
   explicitly do **not** claim (a comparison against commercial SIEMs
   that was never run).

## Algorithm summary

```
BCA(E, window_seconds, patterns):
    group E by actor_key
    within each actor group, sorted by time:
        chain consecutive events where gap <= window_seconds
        score each resulting group against known chain patterns
```

Runtime: O(n log n), dominated by the per-actor sort. This is the same
asymptotic complexity as the v0 reference implementation — BCA's
contribution here is the formalization and graph-native output, not
an asymptotic improvement, and the docstring says so directly rather
than implying otherwise.

## Confidence scoring (v1.0)

| Observed sequence | Confidence | Rationale |
|---|---|---|
| Empty | 0.0 | No technique-bearing events |
| Single technique | 0.20 | No chain to evaluate |
| Exact match to known pattern | 0.95 | Full kill-chain confirmed |
| Strict prefix of known pattern | 0.70 | Attack may be in progress |
| Multiple techniques, no match | 0.40 | Ambiguous — flagged, not dismissed |

This is a deliberate step function, not a continuous score — see the
docstring Section 4 for the explainability-vs-coverage tradeoff this
encodes. v1.1 (planned integration with
[`blackwell-core/confidence-engine`](../confidence-engine/README.md))
replaces this with a continuous, multi-signal score; this module's
function is the documented baseline that improvement will be measured
against.

## Usage

```bash
# Requires the Evidence Graph to exist first:
python3 blackwell-core/evidence-graph/evidence_graph.py
python3 blackwell-core/correlation-bca/bca.py [window_seconds]
```

Output:
- `output/bca_incidents.json` — incident list
- `output/evidence_graph_post_bca.json` — the Evidence Graph with BCA's
  ASSERTION nodes and SUPPORTS edges merged in

## Known limitations

1. **Single-actor scope.** BCA does not detect coordinated multi-actor
   campaigns (same operator, multiple src_ips/accounts). That is entity
   resolution across actor keys — a harder, separate problem, out of
   scope for v1.0.
2. **The bundled pattern library is a worked example, not a general
   claim.** It encodes this project's own VECTOR-I/II chain. A real
   deployment derives this library from MITRE ATT&CK group/campaign
   data or organizational incident history.
3. **Fixed window_seconds.** A single global time window will not
   catch low-and-slow operations spanning hours. Adaptive/multi-scale
   windowing is future work, not attempted here.

## What we measured vs. what we did not claim

We measured: reduction ratio on this project's own telemetry (raw
events → incidents), and an ablation comparing BCA with vs. without
the pattern library. Both are real numbers from this project's own
data — see [`blackwell-core/benchmark`](../benchmark/README.md).

We did not run, and do not claim, a comparison against Splunk ES,
Microsoft Sentinel, or Elastic Security's correlation engines. No such
comparison was performed, so none is reported as if it had been.
