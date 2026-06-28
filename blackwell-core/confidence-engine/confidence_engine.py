#!/usr/bin/env python3
"""
blackwell-core/confidence-engine/confidence_engine.py

BLACKWELL CONFIDENCE ENGINE (BCE) v1.0
Part of the Blackwell Core reasoning layer — OBSIDIAN PROTOCOL

----------------------------------------------------------------------
PROBLEM
----------------------------------------------------------------------
BCA v1.0 (blackwell-core/correlation-bca) assigns confidence using a
four-bucket step function (0.0 / 0.20 / 0.40 / 0.70 / 0.95) keyed on
exact-match / prefix-match / no-match against a pattern library. That
is maximally explainable but throws away information: two "no match"
incidents with very different corroboration (one supported by three
independent telemetry sources, one supported by a single noisy log
line) get the identical 0.40.

BCE replaces the single step function with a continuous score built
from multiple INDEPENDENT signals read directly off the Evidence
Graph, while keeping every component individually inspectable — the
explainability goal from BCA Section 4 is kept, the resolution problem
is fixed.

----------------------------------------------------------------------
FORMAL MODEL
----------------------------------------------------------------------
For an ASSERTION node a in the Evidence Graph, BCE computes:

    confidence(a) = clip01(
          w_c * corroboration(a)
        + w_d * source_diversity(a)
        + w_p * pattern_strength(a)
        - w_x * contradiction_penalty(a)
    )

    w = (w_c=0.35, w_d=0.25, w_p=0.30, w_x=0.40)
    (penalty weight is intentionally larger than any single positive
     weight: one credible contradiction should be able to outweigh
     one corroborating signal, not be diluted by it equally)

SIGNAL DEFINITIONS:

  corroboration(a) ∈ [0,1]:
      1 - 1/(1 + supporting_edge_count(a))
      Diminishing returns on raw count: going from 1 to 2 supporting
      pieces of evidence matters more than going from 8 to 9. This is
      the same diminishing-returns shape ioc-decay/ioc_decay.py uses
      for frequency_boost (log-scale), applied here as a saturating
      function for the same underlying reason: naive evidence counts
      should not be allowed to inflate confidence without bound.

  source_diversity(a) ∈ [0,1]:
      min(distinct_provenance_count(a) / 4, 1.0)
      Three pieces of evidence from the same telemetry source are
      weaker corroboration than three pieces from three different
      sources (auditd + eBPF + Apache log, say). This directly
      operationalizes the same principle ioc-decay applies via its
      source_boost term — independent corroboration is worth more
      than repeated observation from one channel.

  pattern_strength(a) ∈ [0,1]:
      BCA's own match_confidence() output for this assertion,
      rescaled from its [0,0.95] range to [0,1]. BCE does not discard
      BCA's pattern-matching judgment — it incorporates it as one
      signal among several rather than the only signal.

  contradiction_penalty(a) ∈ [0,1]:
      1 - 1/(1 + contradicting_edge_count(a))
      Same saturating shape as corroboration, applied to CONTRADICTS
      edges pointing at this assertion (see
      EvidenceGraph.find_contradictions in blackwell-core/evidence-graph).

----------------------------------------------------------------------
WHY THIS DOES NOT REPLACE BCA's SCORING, IT WRAPS IT
----------------------------------------------------------------------
BCA's pattern_strength signal is still computed by BCA's own
match_confidence function — BCE is explicitly a second pass that adds
corroboration and contradiction signals BCA does not have access to
(BCA only sees one actor's event group at a time; BCE sees the whole
graph, including other assertions and indicators that may bear on the
same conclusion). This mirrors a standard pattern in evidential
reasoning systems: a local scoring function feeding a global belief
aggregation step. We are explicit that this is the standard pattern,
not a novel one — the contribution here is applying it concretely to
this specific evidence model with documented, inspectable weights.

----------------------------------------------------------------------
KNOWN LIMITATIONS
----------------------------------------------------------------------
1. Weights (0.35/0.25/0.30/0.40) are hand-set for the same reason
   BRS's weights are hand-set (see blackwell-core/risk-score-brs
   Section 5): no labeled outcome dataset exists to fit them against.
   This is stated, not hidden.
2. source_diversity assumes provenance strings are a meaningful proxy
   for true source independence. Two modules both reading the same
   underlying auditd stream would count as two distinct provenances
   despite not being truly independent. A more rigorous independence
   model is future work.
3. This is still a hand-engineered scoring function, not a learned
   one. Section 5 of the BRS docstring's framing applies identically
   here: transparent and auditable was chosen over higher potential
   accuracy from an opaque model, as a deliberate stage-appropriate
   tradeoff.
"""

import json
import os
import sys
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "evidence-graph"))
from evidence_graph import EvidenceGraph, NodeKind, EdgeRelation  # noqa: E402

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

WEIGHTS = {
    "corroboration": 0.35,
    "source_diversity": 0.25,
    "pattern_strength": 0.30,
    "contradiction_penalty": 0.40,
}


@dataclass
class ConfidenceResult:
    node_id: str
    label: str
    confidence: float
    components: dict
    rationale: str


def saturating(count: int) -> float:
    """1 - 1/(1+n). 0 at n=0, 0.5 at n=1, 0.75 at n=3, asymptotic to 1."""
    return 1.0 - 1.0 / (1.0 + count)


def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


def score_assertion(graph: EvidenceGraph, node_id: str) -> ConfidenceResult:
    node = graph.nodes[node_id]
    supporting = graph.supporting_evidence(node_id)
    contradicting = graph.contradicting_evidence(node_id)

    corroboration = saturating(len(supporting))
    distinct_sources = len(set(s.provenance for s in supporting))
    source_diversity = min(distinct_sources / 4.0, 1.0)
    pattern_strength = clip01(node.weight)  # node.weight already holds BCA's confidence for ASSERTION nodes
    contradiction_penalty = saturating(len(contradicting))

    confidence = clip01(
        WEIGHTS["corroboration"] * corroboration
        + WEIGHTS["source_diversity"] * source_diversity
        + WEIGHTS["pattern_strength"] * pattern_strength
        - WEIGHTS["contradiction_penalty"] * contradiction_penalty
    )

    rationale = (
        f"corroboration={corroboration:.2f}(n={len(supporting)}, w{WEIGHTS['corroboration']}) "
        f"diversity={source_diversity:.2f}(sources={distinct_sources}, w{WEIGHTS['source_diversity']}) "
        f"pattern={pattern_strength:.2f}(w{WEIGHTS['pattern_strength']}) "
        f"contradiction_penalty={contradiction_penalty:.2f}(n={len(contradicting)}, w{WEIGHTS['contradiction_penalty']})"
    )

    return ConfidenceResult(
        node_id=node_id, label=node.label, confidence=round(confidence, 3),
        components={
            "corroboration": round(corroboration, 3),
            "source_diversity": round(source_diversity, 3),
            "pattern_strength": round(pattern_strength, 3),
            "contradiction_penalty": round(contradiction_penalty, 3),
            "supporting_count": len(supporting),
            "contradicting_count": len(contradicting),
            "distinct_sources": distinct_sources,
        },
        rationale=rationale,
    )


def run_confidence_engine(graph: EvidenceGraph) -> list[ConfidenceResult]:
    targets = [n for n in graph.nodes.values()
               if n.kind in (NodeKind.ASSERTION, NodeKind.CONCLUSION)]
    return [score_assertion(graph, n.node_id) for n in targets]


def main():
    graph = EvidenceGraph.load_from_obsidian_outputs()
    if not graph.nodes:
        print("[!] Evidence Graph is empty. Run the OBSIDIAN PROTOCOL pipeline first.")
        sys.exit(1)

    results = run_confidence_engine(graph)

    print("=" * 70)
    print("  BLACKWELL CONFIDENCE ENGINE (BCE) v1.0")
    print("=" * 70)
    print(f"\n  Scored {len(results)} assertion/conclusion nodes\n")
    for r in sorted(results, key=lambda x: -x.confidence):
        print(f"  {r.confidence:.3f}  {r.label}")
        print(f"    {r.rationale}\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "confidence_scores.json")
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
    print(f"[+] Saved: {out_path}")


if __name__ == "__main__":
    main()
