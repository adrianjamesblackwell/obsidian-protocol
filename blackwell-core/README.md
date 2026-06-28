# BLACKWELL CORE
### Evidence-Driven Security Reasoning Layer — OBSIDIAN PROTOCOL

## What this is

Blackwell Core sits **on top of** the 17-module OBSIDIAN PROTOCOL
pipeline. It does not replace or fork any existing module — every
module under the project root keeps working completely standalone.
Blackwell Core's job is to turn the existing modules' separate outputs
into a single, queryable, auditable evidence structure, and to
synthesize that structure into prioritized, traceable decisions
instead of a pile of dashboards.

The repositioning this represents: the platform's output is not a log
line, a Sigma match, or an IOC. It's an **evidence-grounded security
recommendation** — a conclusion with its supporting reasoning attached
and inspectable. See [`docs/whitepaper/`](../docs/whitepaper/) for the
full research write-up.

## Components, in dependency order

```
EVIDENCE GRAPH (the substrate)
      |
      +--> BCA (Correlation Algorithm) ---------+
      +--> BRS (Risk Score) ---------------------+--> all write back
      |                                          |    into the graph
      v                                          |
CONFIDENCE ENGINE  <-----------------------------+
      |
      +--> KNOWLEDGE GRAPH (entity projection)
      +--> TEMPORAL REASONING (tempo/anomaly analysis)
      +--> EVIDENCE RANKING (analyst-attention priority)
      +--> ATTACK PATH PREDICTION (structural hypotheses)
            |
            v
      DECISION ENGINE (joins everything above)
            |
            +--> technical_briefing.md
            +--> executive_briefing.md
```

| # | Component | One-line summary | README |
|---|---|---|---|
| 1 | Evidence Graph (BEG) | Typed graph of claims and evidence relationships — the substrate everything else reads and writes | [README](evidence-graph/README.md) |
| 2 | Correlation Algorithm (BCA) v1.0 | Formal, graph-native successor to `correlation-engine/correlate.py` | [README](correlation-bca/README.md) |
| 3 | Risk Score (BRS) v1.0 | Formal, graph-integrated successor to `risk-engine`'s composite formula | [README](risk-score-brs/README.md) |
| 4 | Confidence Engine (BCE) | Continuous, multi-signal confidence: corroboration, source diversity, pattern strength, contradiction penalty | [README](confidence-engine/README.md) |
| 5 | Knowledge Graph (BKG) | Entity-relationship view, derived as a pure projection of BEG | [README](knowledge-graph/README.md) |
| 6 | Temporal Reasoning (BTR) | Tempo classification and anomalous-gap detection within an incident's timeline | [README](temporal-reasoning/README.md) |
| 7 | Evidence Ranking (BER) | "What should an analyst look at first" — confidence term deliberately inverted | [README](evidence-ranking/README.md) |
| 8 | Attack Path Prediction (BAPP) | Structural next-step hypotheses from documented ATT&CK transitions — explicitly not forecasting | [README](attack-path-prediction/README.md) |
| 9 | Decision Engine (BDE) | Joins every module above into one prioritized, traceable action list with dual-audience reports | [README](decision-engine/README.md) |
| — | Validation Framework | Synthetic ground-truth tests, ablation studies, literature-referenced context — and an explicit list of what isn't claimed | [README](benchmark/README.md) |

## Running the full reasoning layer

Requires the standard OBSIDIAN PROTOCOL pipeline to have produced
telemetry, threat-intel, and correlation output first (see the
project root [`README.md`](../README.md), "End-to-end run").

```bash
python3 blackwell-core/evidence-graph/evidence_graph.py
python3 blackwell-core/correlation-bca/bca.py
python3 blackwell-core/risk-score-brs/brs.py
python3 blackwell-core/confidence-engine/confidence_engine.py
python3 blackwell-core/knowledge-graph/knowledge_graph.py
python3 blackwell-core/temporal-reasoning/temporal_reasoning.py
python3 blackwell-core/evidence-ranking/evidence_ranking.py
python3 blackwell-core/attack-path-prediction/attack_path_prediction.py
python3 blackwell-core/decision-engine/decision_engine.py
```

Or, as part of the full pipeline including the legacy modules:

```bash
python3 reporting/generate_all_reports.py
```

## Design principles applied consistently across every module here

1. **Every score is traceable to specific evidence**, not just a
   number. `EvidenceGraph.subgraph_for(node_id)` answers "why do you
   believe this" as a graph query.
2. **Hand-set weights are stated as hand-set, not implied to be
   learned or calibrated.** Every module's README says directly that
   it's an auditable scoring function, not a fitted probabilistic
   model — and says what would be needed to make it one (a labeled
   outcome dataset this lab doesn't have).
3. **Limitations are documented in the same file as the algorithm**,
   not in a separate appendix that's easy to skip. Every module's
   docstring has a "Known Limitations" section written at the time the
   algorithm was built, not added defensively afterward.
4. **No claim is made that wasn't actually measured.** See
   [`benchmark/README.md`](benchmark/README.md) for what was tested
   and the explicit list of comparisons that were never run and are
   therefore never reported.
5. **Ambiguity is surfaced, not resolved automatically.**
   Contradicting evidence is flagged (`find_contradictions`), not
   silently adjudicated — the Decision Engine routes ambiguity to a
   human rather than picking a winner.
