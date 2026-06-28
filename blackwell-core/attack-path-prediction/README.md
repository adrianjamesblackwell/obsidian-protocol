# BLACKWELL ATTACK PATH PREDICTION (BAPP) v1.0

### Structural hypothesis generation — explicitly NOT adversary forecasting

## The framing this module insists on

"Attack path prediction" in vendor marketing often implies forecasting
a specific adversary's specific next move. **BAPP does not do that,
and says so directly in its own output.** What it does instead:
given the tactics observed so far in an incident, it projects a small
set of tactics that are *structurally plausible next steps* according
to the well-documented MITRE ATT&CK kill-chain ordering — and for
each one, whether this project's own telemetry would currently detect
it.

Every candidate is generated as a `HYPOTHETICAL`-typed node in the
Evidence Graph — following the same confirmed-vs-hypothetical
distinction `risk-graph/risk_graph.py` already established — so it can
never be confused with a confirmed finding when the graph is queried
or rendered.

## How it works

```
predict_next_tactics(observed_sequence):
    last_tactic = tactic_of(observed_sequence[-1])
    candidates = { (last_tactic, t, weight) in TACTIC_TRANSITION }
    for each candidate: check telemetry-gap output for detectability
    return candidates, ranked by weight
```

The transition table mixes this project's own two-vector chain
(narrow but real — actually observed) with well-documented general
ATT&CK post-exploitation transitions (added for completeness, **not**
validated against a real campaign corpus — stated directly rather
than implied as equally strong evidence).

## Why this stops at the tactic level, not the technique level

MITRE ATT&CK has ~14 tactics but hundreds of techniques. "Lateral
Movement commonly follows Privilege Escalation" is defensible from
public kill-chain literature. "The next specific technique will be
T1021.004 rather than T1021.001" would need either a much larger
labeled campaign corpus than this lab has, or would be speculation
dressed up as prediction. BAPP stops at the granularity its inputs
can actually support.

## Usage

```bash
python3 blackwell-core/attack-path-prediction/attack_path_prediction.py
```

Output: `output/attack_path_predictions.json`, plus an updated Evidence
Graph with `HYPOTHETICAL` conclusion nodes.

## Known limitations

1. **Not adversary forecasting.** This must never be presented as "the
   system predicts the attacker will do X." Correct framing: "if this
   operation continues, here are tactics structurally consistent with
   documented kill-chains, and whether we'd currently detect them."
2. **The transition table is partly hand-curated for completeness**
   and has not been validated against a large real-world campaign
   corpus.
3. **No probability calibration.** Weights are ordinal (for ranking
   candidates against each other), not calibrated probabilities of
   what will actually happen.
