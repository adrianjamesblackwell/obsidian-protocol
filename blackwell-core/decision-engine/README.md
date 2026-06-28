# BLACKWELL DECISION ENGINE (BDE) v1.0

### The platform's actual output layer — synthesis, not a new scoring model

## Problem

Every upstream module produces one piece of reasoning: BCA correlates,
BRS scores risk, BCE assigns confidence, BER ranks for attention, BTR
characterizes timing, BKG maps entities, BAPP projects hypothetical
next steps. None of them individually answers what a SOC actually
needs at the end of a shift: "given everything we know, what should we
do, in what order, and why." That synthesis is BDE's job.

## What BDE does

BDE introduces **no new scoring formula**. It is a join:

1. **One prioritized action list** — BER's ranking, enriched per item
   with BRS's risk band, root-cause's preventive actions, and BAPP's
   "if this continues" hypothesis. One list instead of seven
   dashboards.
2. **A why-explanation per item** — calls
   `EvidenceGraph.subgraph_for(node_id)` and renders it as a short
   evidence narrative, so every recommendation traces back to the
   specific evidence nodes and edges behind it.
3. **Two reports from the same decision object** — a technical
   briefing and an executive briefing, generated from one underlying
   join rather than two independently written summaries that could
   drift apart and tell the two audiences subtly different things
   about the same incident.

## Why a join, not a model

Composing existing, already-computed numbers is what makes every
statement in the output traceable. The executive narrative is built
from hand-written string templates with conditionals — not a language
model — specifically so every sentence is directly traceable to a
specific upstream number. An LLM-generated executive summary would
read more fluently but would reintroduce exactly the kind of
unverifiable claim this whole platform exists to avoid.

## Usage

Requires BER, BRS, root-cause, BAPP, and (optionally) BTR to have
already produced output:

```bash
python3 blackwell-core/decision-engine/decision_engine.py
```

Output:
- `output/decision_items.json` — the full joined decision list
- `output/technical_briefing.md` — analyst-facing, full evidence chain
- `output/executive_briefing.md` — single-page, traceable to the same
  numbers

## Known limitations

1. **Missing upstream data is shown as missing, never estimated.** If
   a module hasn't been run, the corresponding enrichment is marked
   "not available" rather than defaulted — the same principle
   `risk-engine` and `ioc-decay` already state for their own gaps.
2. **No snapshot/version reconciliation.** BDE assumes every upstream
   module ran against the same Evidence Graph snapshot. Joining BER
   from one run against BAPP from a later one would silently produce
   a stale join — there is no check for this in v1.0.
3. **Template-based narrative generation is rigid by design.** It
   trades fluency for traceability; that tradeoff is deliberate, not
   accidental.
