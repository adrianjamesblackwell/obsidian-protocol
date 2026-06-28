# Evidence-Driven Security Reasoning: The Blackwell Core Architecture

### A Research Whitepaper on the OBSIDIAN PROTOCOL Platform

**Classification:** Educational / Portfolio Research. All experimental
results in this paper were produced in an isolated, internet-disconnected
Docker lab using publicly known, patched CVEs. No third-party or live
system was accessed at any point.

---

## Abstract

Security operations centers face three interlocking, well-documented
problems: alert fatigue from high-volume, low-context telemetry;
detection coverage that is felt but not measured; and a structural gap
between what detection tools output (alerts, IOCs, rule matches) and
what an analyst or executive actually needs (a reasoned, prioritized,
traceable decision). Most published and commercial tooling addresses
these as separate point problems. This paper presents **Blackwell
Core**, a reasoning layer built on top of a 17-module security
telemetry, correlation, and reporting pipeline (OBSIDIAN PROTOCOL),
that treats them as one structural problem: the absence of a shared,
queryable evidence substrate beneath detection and response tooling.

We introduce the **Blackwell Evidence Graph (BEG)**, a typed,
attributed graph model in which nodes are claims — not entities — and
edges are typed evidential relationships (`SUPPORTS`, `CONTRADICTS`,
`CAUSES`, `TEMPORALLY_PRECEDES`, `CO_OCCURS_WITH`, `DERIVED_FROM`). We
then present five reasoning passes that read and write this graph: a
formally specified correlation algorithm (BCA), a composite,
graph-integrated risk score (BRS), a continuous multi-signal
confidence model (the Confidence Engine), an entity-relationship
projection (the Knowledge Graph), and a tempo/anomaly characterization
pass (Temporal Reasoning). On top of these we build an
analyst-attention ranking algorithm (Evidence Ranking) with a
deliberately inverted confidence term, a bounded structural-hypothesis
generator for plausible next attack tactics (Attack Path Prediction)
that explicitly disclaims adversary forecasting, and a synthesis layer
(the Decision Engine) that joins all of the above into a single
prioritized, fully traceable action list rendered as two
audience-specific briefings from one underlying object.

We evaluate the system three ways, chosen specifically because they
are measurable without fabrication: a synthetic, hand-labeled
ground-truth fixture for correlation-boundary correctness; an ablation
study isolating the contribution of kill-chain pattern matching from
temporal/actor grouping on the system's own real lab telemetry; and a
literature-referenced context table that is explicitly **not**
presented as a benchmark this system was run against. We report what
we measured, and we report, by name, what we did not — no comparison
against any commercial SIEM correlation engine was performed, and none
is claimed.

**Keywords:** security operations, evidence graphs, alert correlation,
risk scoring, explainable security analytics, MITRE ATT&CK, detection
engineering, purple team validation.

---

## 1. Introduction

### 1.1 The problem, restated precisely

The security industry has converged on a roughly correct diagnosis of
SOC pain that is nonetheless usually treated as three unrelated
products: a correlation/SOAR layer to reduce alert volume, a coverage
or "purple team" layer to measure detection completeness, and a
reporting layer to translate technical findings for non-technical
stakeholders. These are typically built, sold, and operated as
separate systems with separate data models. The practical consequence
is that an analyst answering "why does the system believe this is a
real incident" must manually reconstruct the answer from logs,
tickets, and memory — the correlation engine's confidence number, the
risk engine's score, and the coverage tool's gap report do not share a
queryable structure that links them.

We treat this as a single structural deficiency rather than three
separate feature gaps: **there is no shared evidence substrate**
beneath the tools that consume and produce security findings. Each
tool's output is a terminal artifact — a JSON file, a dashboard row, a
PDF page — rather than a node in a graph that the next tool can read,
extend, and query.

### 1.2 Contribution

This paper makes the following concrete contributions, each grounded
in a working, executable implementation rather than a purely
conceptual design:

1. **A formal evidence graph model (BEG)** that distinguishes claims
   (`RAW_EVENT`, `INDICATOR`, `ASSERTION`, `CONCLUSION`) from the
   typed evidential relationships between them, and that is
   explicitly *not* an entity-relationship graph — the latter is
   derived from BEG as a projection (Section 3.5), not maintained
   as a parallel structure that can drift out of sync with the
   evidence that justifies it.

2. **A formally specified correlation algorithm (BCA)** restating an
   existing actor+time-window+pattern-match approach as an explicit
   problem statement, pseudocode, and scoring function, with a stated
   evaluation protocol (Section 5) rather than an implicit one.

3. **A composite risk-scoring formula (BRS)** that incorporates the
   system's own measured detection coverage as a first-class,
   equally-weighted risk component alongside external threat
   signals (CVSS, KEV status, campaign breadth) — operationalizing
   the principle that severity alone is an incomplete prioritization
   signal without an organization's own observability folded in.

4. **A continuous, multi-signal confidence model** that replaces a
   four-bucket step function with a weighted combination of
   corroboration, source diversity, pattern strength, and a
   contradiction penalty weighted higher than any single positive
   term — because one credible contradiction should be able to
   outweigh one corroborating signal, not be diluted by it equally.

5. **An analyst-attention ranking algorithm** that deliberately
   *inverts* the confidence term relative to what a naive design
   would do, and states explicitly why: ranking by raw confidence
   would systematically starve exactly the ambiguous, high-severity
   cases that most need human judgment.

6. **A bounded, explicitly-scoped structural hypothesis generator**
   for plausible next attack tactics, built to resist the common
   overclaim in this space — we generate tactic-level, not
   technique-level, hypotheses, and we state in the algorithm's own
   output that this is not adversary forecasting.

7. **A synthesis layer (the Decision Engine)** that performs no new
   scoring, only a traceable join, producing two audience-specific
   reports — technical and executive — from one underlying decision
   object, specifically to prevent the two audiences from being told
   subtly different things about the same incident.

8. **An evaluation methodology built around an explicit non-claims
   list** (Section 5.4) — stating, by name, the comparisons this
   project did not run, because in a domain prone to fabricated
   benchmarking, what you refuse to claim is as load-bearing as what
   you do.

### 1.3 Scope and what this paper does not claim

This is not a paper about a production-deployed system processing
real SOC alert volumes. The underlying attack chain (Section 2) is two
well-known, patched CVEs exploited in an isolated lab. The
contribution is the reasoning architecture and the algorithms that
operate on its output — designed to be evaluated honestly at the scale
available, and designed so that scaling the underlying telemetry
volume up does not require rewriting the evidence model.

We also do not claim novelty for the standard patterns we apply
(local-score-then-global-belief-aggregation in the Confidence Engine,
graph-projection-from-claims-to-entities in the Knowledge Graph,
tactic-transition modeling in Attack Path Prediction) — these are
named in their respective sections as applications of known patterns
to this specific evidence model, not as new general techniques.

---

## 1.4 Related Work and Positioning

We position Blackwell Core relative to four adjacent bodies of work,
stating directly where our contribution does and does not overlap
with each.

### 1.4.1 SIEM and SOAR correlation engines

Commercial correlation engines (Splunk Enterprise Security's notable
events framework, Microsoft Sentinel's fusion correlation rules,
Elastic Security's detection rule chaining) solve a closely related
problem: reducing raw alert volume into investigable units. Published
vendor descriptions of these systems emphasize rule-based and,
increasingly, ML-assisted correlation across large alert volumes. Our
contribution is not a claim of superior correlation accuracy at that
scale — no such comparison was run (Section 5.4) — but a different
emphasis: these systems' correlation decisions are typically terminal
outputs (a grouped "notable event," a "fused alert") rather than
nodes in a queryable evidence structure that downstream risk scoring,
confidence modeling, and reporting can read and extend without
re-deriving context. BCA's distinguishing structural property is not
its grouping logic (which is comparatively simple — actor and time
window) but that its output is a first-class graph object with
explicit `SUPPORTS` edges back to source telemetry, inspectable by
every other module in this paper.

### 1.4.2 Vulnerability prioritization frameworks

FIRST's Exploit Prediction Scoring System (EPSS) and the broader
Stakeholder-Specific Vulnerability Categorization (SSVC) framework
both address the same underlying complaint BRS is built around: CVSS
alone is an insufficient prioritization signal. EPSS uses a
machine-learned model trained on observed exploitation activity to
produce a probability of exploitation within a future window; SSVC
uses a decision-tree-structured set of stakeholder-specific questions.
BRS differs from both in mechanism (a fixed-weight linear combination,
not a learned model or decision tree) and in the specific signal it
adds that neither EPSS nor SSVC use as a primary input: a quantity
*the organization itself measured* — its own Purple Team detection
coverage for the CVE in question — weighted equal to external
severity. We are explicit that BRS's weights are hand-set rather than
learned (Section 4.3.4), which is a real difference in rigor from
EPSS's trained model, not a stylistic choice we present as equivalent.
A natural future direction (Section 7.2) is incorporating EPSS itself
as one of BRS's input signals rather than treating the two frameworks
as competitors.

### 1.4.3 Security knowledge graphs

Graph-based security data models are well established, particularly
for representing attack surfaces, asset relationships, and attack
paths (e.g., attack graph generation in network security research,
and commercial "exposure graph" products). Most of this work models
*entities* and their relationships — hosts, vulnerabilities, network
paths — which is precisely the structure we build as the Knowledge
Graph (Section 3.5), but deliberately treat as a *derived projection*
rather than the primary data model. The distinction we draw — that
claims, not entities, should be the graph's primary node type, because
only claims carry confidence and evidential support — is, to our
knowledge, not the typical framing in the security knowledge graph
literature, which more often treats confidence as an edge or node
attribute on an entity graph rather than introducing a separate claim
layer that the entity graph is derived from. We present this as the
paper's clearest structural contribution relative to this body of
work, while noting plainly that we have not conducted a systematic
literature survey sufficient to claim this distinction is wholly
novel — only that it is not the default framing we observed in the
adjacent commercial and open-source tools we examined while building
this system.

### 1.4.4 Explainable AI and evidential reasoning

The Confidence Engine's local-score-then-global-aggregation structure
and the general principle of keeping every component of a composite
score individually inspectable both draw on standard practice in
explainable AI and evidential reasoning systems (e.g.,
Dempster-Shafer-style evidence combination, and the general
"glass-box over black-box" design stance argued for in interpretable
ML literature). We do not claim to introduce a new evidential
combination rule — the specific weighted-sum-with-asymmetric-penalty
formula in Section 4.2.2 is a straightforward application of that
general stance to this specific evidence model, and we say so
directly rather than presenting standard practice as novel technique.

### 1.4.5 MITRE ATT&CK-based attack path and behavior modeling

Attack Path Prediction's tactic-transition approach is related to, but
narrower in scope than, published work on attack graph generation and
ATT&CK-based threat modeling, which frequently models technique-level
or even procedure-level transitions using larger campaign corpora than
this project has access to. We deliberately constrain BAPP to
tactic-level transitions for exactly this reason (Section 4.7.3) —
matching the claim's granularity to the evidence actually available,
rather than producing a technique-level prediction that the available
data cannot support credibly.

---

## 2. System Context: The Underlying Operation

Blackwell Core is built on top of, and evaluated using the output of,
a 17-module platform (OBSIDIAN PROTOCOL) that reproduces a real,
documented CVE chain in an isolated Docker range:

| Vector | CVE | Component | Type | CVSS | KEV Status |
|---|---|---|---|---|---|
| VECTOR-I | CVE-2021-41773 / CVE-2021-42013 | Apache HTTPD 2.4.49 | Path Traversal -> RCE | 9.8 | Actively scanned by the AndroxGh0st botnet |
| VECTOR-II | CVE-2021-4034 ("PwnKit") | polkit/pkexec | Local Privilege Escalation | 7.8 | Undetected for 13 years, added to KEV in 2022 |

The operation's full lifecycle — exploitation, hybrid telemetry
collection (auditd + eBPF + Apache access log), detection validation,
risk scoring, root-cause analysis, and reporting — is automated across
the modules documented in the project's root
[`README.md`](../../README.md). Blackwell Core consumes these modules'
output files as its primary data source (Section 3.4) and does not
require any additional telemetry source of its own.

This scope is deliberately modest in volume (a handful of attack
steps, a handful of telemetry events) and deliberately real in
substance (an actual exploited CVE chain, actual measured detection
coverage, actual CVSS/KEV data fetched from NVD and CISA). Section 5
addresses directly what can and cannot be concluded from evaluating
reasoning algorithms against a dataset of this size.

---

## 3. The Blackwell Evidence Graph

### 3.1 Motivation: claims, not entities

A natural first instinct when building a "security knowledge graph" is
to model entities — hosts, users, IPs, CVEs — and the relationships
between them. This is a reasonable and common design, and we build
exactly this view (Section 3.5), but we do not make it the *primary*
structure, for a specific reason: entities don't have confidence
levels or evidential support. A host doesn't have a `SUPPORTS` edge;
a *claim about* that host does. Conflating "what entities exist" with
"what we believe and how strongly" produces a graph that cannot
represent the central object a SOC actually reasons about: a
conclusion, its supporting evidence, and the strength of that support.

### 3.2 Formal model

A Blackwell Evidence Graph is a typed, directed, attributed multigraph
`G = (V, E)`.

**Nodes** (`V`) are one of four kinds:

| Kind | Meaning | Typical producer |
|---|---|---|
| `RAW_EVENT` | An atomic telemetry observation | Hybrid telemetry pipeline (auditd/eBPF/Apache) |
| `INDICATOR` | An external threat-intelligence fact | NVD/KEV fetch, IOC decay engine |
| `ASSERTION` | A claim derived from other nodes | Correlation (BCA), root-cause analysis |
| `CONCLUSION` | A claim the system is prepared to act on | Risk scoring (BRS), structural hypotheses (BAPP) |

Each node carries an intrinsic `weight in [0,1]` — its reliability in
isolation, independent of corroboration — and a `provenance` string
identifying the producing module or source.

**Edges** (`E`) are one of six relation types: `SUPPORTS`,
`CONTRADICTS`, `TEMPORALLY_PRECEDES`, `CAUSES`, `CO_OCCURS_WITH`, and
`DERIVED_FROM`, each carrying a `strength in [0,1]` and a free-text
`rationale`.

### 3.3 Query primitives

The graph exposes a small set of primitives that every downstream
reasoning pass is built from:

- `supporting_evidence(n)` / `contradicting_evidence(n)` — direct
  typed neighbors.
- `find_contradictions()` — a single O(E) pass over `CONTRADICTS`
  edges. This function deliberately returns flagged ambiguities
  rather than resolving them. Automatic contradiction resolution in
  security evidence is, in our judgment, an unsolved problem in
  general, and a confidently wrong automatic resolution is a worse
  failure mode than a correctly flagged ambiguity surfaced to a human.
  This is the single most consequential design choice in the entire
  evidence model, and it propagates: the Decision Engine (Section
  4.8) routes contradictions to a human rather than picking a winner.
- `bounded_path(start, end, max_hops)` — bounded BFS, used by Attack
  Path Prediction (Section 4.7) to ask whether a plausible evidentiary
  chain exists between an initial-access node and a hypothetical
  impact node within a fixed inferential-hop budget.
- `subgraph_for(node, depth)` — local neighborhood extraction. This is
  the literal implementation of "why do you believe this": the
  Decision Engine calls this for every item in its output list to
  produce a human-readable evidence narrative (Section 4.8.2).

### 3.4 Construction from the existing pipeline

`EvidenceGraph.load_from_obsidian_outputs()` ingests three existing
OBSIDIAN PROTOCOL output files — the unified telemetry timeline, the
threat-intelligence fetch results, and the correlation engine's
incident output — and converts them into `RAW_EVENT`, `INDICATOR`, and
`ASSERTION` nodes respectively, with `SUPPORTS` edges connecting raw
events to the incidents they were grouped into. Every legacy module
continues to function standalone; this construction step is purely
additive.

### 3.5 The Knowledge Graph as a derived projection

The Blackwell Knowledge Graph (BKG) answers the more familiar
entity-centric question — "what is this host's/user's/CVE's
relationship to everything else" — but is computed as a **pure
function** of the Evidence Graph rather than maintained independently.
For every evidence node, a fixed extraction schema (varying by node
kind) pulls out zero or more entities (host, user, IP, CVE, vendor);
any two entities co-extracted from the *same* evidence node receive a
`RELATED_TO` edge whose strength is the mean weight of the licensing
node(s). This guarantees that BKG is always exactly as current as the
evidence that justifies it, and that "why does the graph believe this
relationship" always resolves to a real, inspectable Evidence Graph
node — never to a second, independently-updated source of truth that
could silently drift out of sync.

### 3.6 Complexity and scale

| Operation | Complexity |
|---|---|
| Graph construction from N events, M indicators | O(N + M) |
| `find_contradictions` | O(E), single pass |
| `bounded_path(max_hops=h)` | O(b^h), branching factor b |
| `subgraph_for(depth=d)` | O(b^d) |
| Knowledge Graph projection | O(V x k^2), k = max entities per node (bounded, k <= 4 in the current schema) |

The graph is held in memory and serialized to JSON, adequate at lab
scale (hundreds to low thousands of nodes). The node/edge schema is
deliberately kept property-graph-shaped specifically so a migration to
a dedicated graph database (Neo4j, JanusGraph) at SOC scale would be a
storage-layer change, not a model rewrite (Section 7.2).
## 4. The Reasoning Algorithms

### 4.1 Blackwell Correlation Algorithm (BCA) v1.0

#### 4.1.1 Problem statement

Given evidence nodes `E = {e_1, ..., e_n}`, each with an actor key
`actor(e)` (derived from `src_ip` for network events or `user` for
host events), a timestamp `t(e)`, and an optional MITRE technique
`technique(e)`, find a partition of `E` into incident groups
`I = {I_1, ..., I_m}` such that within each group all events share an
actor key (actor closure), the group is temporally connected under a
fixed window threshold (temporal closure — equivalent to single-link
clustering with a distance threshold), and the resulting technique
sequence is assigned a confidence score via Section 4.1.3's scoring
function.

We state this formally specifically because it clarifies what BCA is
*not*: it is single-actor temporal clustering composed with sequence
scoring, not a general multi-actor correlation algorithm. It does not
claim to detect coordinated campaigns spanning multiple actor keys
(Section 4.1.5).

#### 4.1.2 Algorithm

```
BCA(E, window_seconds, patterns):
    partition E by actor(e)
    for each actor's event group, sorted by time:
        chain consecutive events where gap <= window_seconds
        score each resulting chain against the pattern library
    return all chains with their scores
```

Runtime is `O(n log n)`, dominated by the per-actor sort — unchanged
from a naive reference implementation. BCA's contribution at the
algorithmic level is the formalization and the graph-native output
(every incident becomes an `ASSERTION` node with `SUPPORTS` edges back
to its member events), not an asymptotic improvement, and we state
this directly rather than overstating what changed.

#### 4.1.3 Confidence scoring

| Observed sequence | Confidence | Rationale |
|---|---|---|
| Empty | 0.0 | No technique-bearing events |
| Single technique | 0.20 | No chain to evaluate |
| Exact match to a known pattern | 0.95 | Full kill-chain confirmed |
| Strict prefix of a known pattern | 0.70 | Attack may be in progress |
| Multiple techniques, no match | 0.40 | Ambiguous — flagged, not dismissed |

This is a deliberate step function, prioritizing explainability
("70%, because this is a recognized prefix of a known chain") over the
graceful degradation a continuous score would offer. Section 4.2
(Confidence Engine) is the documented, measured improvement over this
baseline — built as a second pass specifically so the explainability
property of BCA's local score is preserved while extending it with
graph-wide signals BCA cannot see.

#### 4.1.4 Why a step function, not a learned score, in v1.0

A continuous or learned score would handle noisy partial matches more
gracefully. We chose to ship the explainable, auditable model first
and treat a move to a continuous or learned model as a *measured*
future improvement (Section 4.2) rather than a default starting point
— consistent with the same design stance taken throughout this project
(see Section 4.3's discussion of BRS's weights).

#### 4.1.5 Known limitations

1. **Single-actor scope.** BCA does not detect coordinated multi-actor
   campaigns (the same operator pivoting through multiple accounts or
   source IPs) — that is an entity-resolution problem across actor
   keys, explicitly out of scope.
2. **The bundled pattern library is a worked example.** It encodes
   this project's own two-vector chain; a production deployment would
   derive it from MITRE ATT&CK's published group/campaign data.
3. **Fixed time window.** A single global `window_seconds` parameter
   cannot detect low-and-slow operations spanning hours without
   adaptive or multi-scale windowing, which is not attempted here.

---

### 4.2 Blackwell Confidence Engine (BCE)

#### 4.2.1 Motivation

BCA's step function gives two unrelated "no pattern match" incidents
the identical 0.40 confidence even when one is corroborated by four
independent telemetry sources and the other by a single noisy log
line. This is a real loss of information that a second reasoning pass
over the *whole graph* — rather than one actor's isolated event group
— can recover.

#### 4.2.2 Model

For an assertion node `a`:

```
confidence(a) = clip01( 0.35*corroboration(a)
                       + 0.25*source_diversity(a)
                       + 0.30*pattern_strength(a)
                       - 0.40*contradiction_penalty(a) )
```

`corroboration` and `contradiction_penalty` both use the saturating
function `1 - 1/(1+n)`, giving diminishing returns on raw evidence
count — going from one supporting node to two matters more than going
from eight to nine. `source_diversity` rewards corroboration from
*distinct* provenances over repeated observation from one channel.
`pattern_strength` reuses BCA's own score, rescaled, rather than
discarding it. The penalty term's weight (0.40) exceeds every single
positive term's weight by design: one credible contradiction should be
able to outweigh one corroborating signal, not be diluted by it
equally in a simple average.

#### 4.2.3 Relationship to standard evidential-reasoning patterns

This is the standard local-score-then-global-belief-aggregation
pattern used broadly in evidential reasoning systems. We name this
directly: the contribution here is the specific, inspectable weighting
applied to this evidence model, not the invention of the pattern
itself.

#### 4.2.4 Known limitations

Weights are hand-set, for the reason stated throughout this paper: no
labeled outcome dataset exists yet against which to fit them.
`source_diversity` trusts provenance strings as a proxy for true
independence — two modules reading the same underlying log stream
would count as independent even though they aren't.

---

### 4.3 Blackwell Risk Score (BRS) v1.0

#### 4.3.1 Formula

```
BRS(v) = 0.25 * threat_cvss(v)
       + 0.30 * active_exploitation(v)
       + 0.20 * campaign_breadth(v)
       + 0.25 * defense_gap(v)
```

All four signals normalized to `[0,100]`; bands: CRITICAL `[80,100]`,
HIGH `[60,80)`, MEDIUM `[40,60)`, LOW `[0,40)`.

| Signal | Source | Captures |
|---|---|---|
| `threat_cvss` | NVD | Classic severity, rescaled |
| `active_exploitation` | CISA KEV | KEV membership, confirmed ransomware use |
| `campaign_breadth` | Threat intel | Known botnets, sector diversity |
| `defense_gap` | **This project's own Purple Team output** | `100 - measured_coverage` |

#### 4.3.2 The central design claim, and why it's falsifiable

`defense_gap` is weighted equal to `threat_cvss` (both 0.25). This is
the single decision that distinguishes BRS from a CVSS-plus-KEV
lookup: two vulnerabilities with identical external severity and
identical campaign data can land in different risk bands if one is
well-covered by this project's own detection layer and the other is
not. The claim is falsifiable, not asserted, because `defense_gap` is
computed from real, measured Purple Team output — if coverage
improves, the score visibly drops, and that can be checked against the
actual `coverage_results.json` the Purple Team module produced.

#### 4.3.3 Sensitivity

Under the bundled weights, BRS moves 0.30 points per point of
`active_exploitation` movement, 0.25 per `threat_cvss` or
`defense_gap` point, and 0.20 per `campaign_breadth` point — i.e., BRS
is most sensitive, per unit, to confirmed active exploitation. This
sensitivity profile is a designed property, not an emergent surprise,
and the Validation Framework (Section 5) is positioned to check it
empirically rather than only asserting it.

#### 4.3.4 Known limitations

Weights are hand-set, framed honestly as an auditable scoring
function — in the spirit of how EPSS or FAIR present their own
components — rather than implied to be a calibrated probability
model. `defense_gap` inherits whatever limitations the Purple Team
module's own coverage measurement has: a shallow rule that technically
fires will understate real risk.

---

### 4.4 Blackwell Knowledge Graph (BKG)

Covered in Section 3.5 as a derived projection of the Evidence Graph.
Restated briefly here for completeness of the algorithm catalogue: BKG
extracts typed entities (host, user, IP, CVE, vendor) per evidence
node via a fixed schema, and licenses a `RELATED_TO` edge between any
two entities that co-occur on the same evidence node, with traceability
back to the licensing node(s) preserved on the edge itself.

---

### 4.5 Blackwell Temporal Reasoning (BTR)

#### 4.5.1 Motivation

BCA's window-based grouping cannot distinguish an automated exploit
chain (sub-second to low-second inter-step gaps, low variance) from a
human operator manually working the same technique sequence (minute-
scale gaps, high variance, occasional long pauses for decision-making)
— both can produce the identical technique sequence within the same
time window.

#### 4.5.2 Measures

For the sorted member events of an incident, BTR computes the
inter-event interval list and derives:

- **`tempo_class`**: a heuristic bucketing of the median interval —
  `MACHINE_SPEED` (<2s), `RAPID` (<30s), `DELIBERATE` (<300s),
  `SLOW_AND_LOW` (>=300s).
- **`regularity`**: `1 - coefficient_of_variation(intervals)`, clipped
  to `[0,1]` — high regularity suggests scripted execution, low
  regularity suggests human pacing. This adapts the standard
  coefficient-of-variation statistic to attacker dwell-time; we do not
  present this as a novel statistical method.
- **`anomalous_gap_indices`**: gaps exceeding 3x the median, flagged
  as candidate points where the operator may have done something not
  captured by current telemetry. This is the temporal analogue, within
  a single incident's timeline, of the Telemetry Gap module's
  "what are we blind to" question across the whole platform.

Every computed gap, anomalous or not, is written back into the
Evidence Graph as a `TEMPORALLY_PRECEDES` edge, making "is this gap
odd" a graph-queryable fact rather than a number visible only in this
module's own output.

#### 4.5.3 Known limitations

Thresholds are heuristic, chosen by inspecting this project's own lab
timing, not derived from a labeled corpus of automated-vs-manual
attacker behavior. `regularity` is statistically noisy at the small
event counts typical of a short lab chain (2-3 intervals). Anomalous
gaps are statistical outliers, not causal explanations — a flagged
gap could mean an operator paused to think, a C2 beacon interval, or
unrelated activity that happened to fall inside the same actor+window
grouping.

---

### 4.6 Blackwell Evidence Ranking (BER)

#### 4.6.1 The distinction this algorithm exists to make explicit

Confidence ("how much should the system believe this") and triage
priority ("how urgently should a human look at this") are frequently
conflated into one score. We argue they should not be: a
high-confidence conclusion is, by definition, one the system is
already fairly sure about, and a human re-checking it adds
comparatively little marginal value. A low-confidence,
high-severity conclusion is exactly the case where human judgment
resolves the most ambiguity before a decision to act. A ranking by raw
confidence (descending) would systematically push exactly these
high-value-to-review cases to the bottom of an analyst's queue.

#### 4.6.2 Formula

```
priority(a) = 0.35*severity(a) + 0.20*(1 - confidence(a)) + 0.20*recency(a) + 0.25*blast_radius(a)
```

The `(1 - confidence(a))` term is the inversion described above,
labeled explicitly in the algorithm's own rationale output as
"inverted-by-design" — precisely because this is the part of the
formula most likely to be implemented backwards by a less careful
design, and we want that fact visible at the point of use, not only in
documentation that might not be read.

`recency` uses an exponential-decay shape (`exp(-age_hours/24)`) from
the same decay family already used by the IOC Decay engine elsewhere
in this platform, applied here to finding staleness rather than IOC
staleness. `blast_radius` is computed via the Knowledge Graph
projection's entity count for the node — the one BER signal that
depends on another Blackwell module's output, because blast radius is
fundamentally a graph-connectivity question.

#### 4.6.3 Known limitations

Weights are hand-set. `recency` is computed at scoring time, producing
a point-in-time snapshot rather than a live-updating rank. `blast_radius`
via raw entity count is a crude impact proxy that does not distinguish
a finding touching several disposable test hosts from one touching
several domain controllers — there is no asset-criticality data source
in this lab to weight by, and none is fabricated to fill that gap.

---

### 4.7 Blackwell Attack Path Prediction (BAPP)

#### 4.7.1 The framing this algorithm insists on

"Attack path prediction" is frequently presented, in vendor marketing
particularly, as forecasting a specific adversary's specific next
move. BAPP does not do this, and is built specifically to resist being
described that way. What it computes is narrower and fully verifiable:
given the tactics observed so far in an incident, it projects a small
set of tactics that are *structurally plausible* next steps under the
well-documented MITRE ATT&CK kill-chain ordering, and for each
candidate, whether this project's own telemetry would currently detect
it.

#### 4.7.2 Method

A fixed tactic-transition table mixes this project's own observed
two-vector chain (narrow, but empirically real) with well-documented
general ATT&CK post-exploitation transitions (added for completeness,
explicitly **not** validated against a real campaign corpus). Given
the last observed tactic in an incident's technique sequence, BAPP
looks up outbound transitions, ranks them by transition weight, and
cross-references each against the Telemetry Gap module's own output to
state plainly whether the hypothesized next step would currently be
detectable. Every candidate is written into the Evidence Graph as a
`HYPOTHETICAL`-typed `CONCLUSION` node, connected via `DERIVED_FROM`,
following the same confirmed-vs-hypothetical distinction the
project's existing Risk Graph module already established — so a
hypothesis can never be confused with a confirmed finding when the
graph is rendered or queried.

#### 4.7.3 Why tactic-level, not technique-level

MITRE ATT&CK documents roughly 14 tactics but hundreds of techniques.
A claim like "Lateral Movement commonly follows Privilege Escalation"
is defensible from public kill-chain literature at the tactic level. A
claim like "the next specific technique will be T1021.004 rather than
T1021.001" would require either a much larger labeled corpus of real
campaign sequences than this lab has, or would be speculation
presented as prediction. BAPP stops at the level of granularity its
inputs can actually support — a deliberate scope boundary, not a
limitation discovered after the fact.

#### 4.7.4 Known limitations

This is structural hypothesis generation, not forecasting, and must
never be presented to a stakeholder as "the system predicts the
attacker will do X." The transition table's general-ATT&CK portion is
unvalidated against a real campaign corpus. Transition weights are
ordinal, for ranking candidates against each other, and are not
calibrated probabilities of what will actually happen.

---

### 4.8 Blackwell Decision Engine (BDE) v1.0

#### 4.8.1 Role: synthesis, not a new model

Every algorithm above answers one question. None of them, individually,
answers what a SOC actually needs at the end of a shift: given
everything currently known, what should be done, in what order, and
why. BDE introduces no new scoring formula — its entire contribution
is a disciplined join across BER's ranking, BRS's risk band, the
root-cause module's preventive actions, and BAPP's hypothetical next
steps, keyed by shared CVE/node identifiers, walked through
`EvidenceGraph.subgraph_for()` for a traceable evidence narrative per
item.

#### 4.8.2 Two reports, one decision object

BDE renders two outputs — a technical briefing (full evidence chain,
every component score, temporal notes, hypothetical next steps) and an
executive briefing (top-priority items, plain-language risk band,
single recommended action, a visibility-gap summary) — from the *same*
underlying decision list. This is a direct structural answer to a
problem this platform's own legacy reporting layer already names: "the
CEO doesn't read Sigma rules." Generating both reports from one join,
rather than maintaining two independently-written summaries, is what
prevents the technical and executive audiences from ever being told
subtly different things about the same incident.

#### 4.8.3 Why templates, not a language model, for the executive narrative

The executive narrative is generated by hand-written string templates
with conditionals, not a generative model, specifically so every
sentence in the output is mechanically traceable to a specific
upstream number. A language-model-generated executive summary would
likely read more fluently, but would reintroduce exactly the class of
unverifiable claim this entire reasoning layer was built to eliminate.
This tradeoff — rigidity for traceability — is deliberate and stated
directly rather than presented as an oversight to fix later.

#### 4.8.4 Known limitations

Missing upstream module output is shown as explicitly absent, never
estimated — consistent with the same principle already applied
throughout this platform (Section 4.3.4). BDE assumes every upstream
module ran against the same Evidence Graph snapshot; there is no
version/snapshot reconciliation check in v1.0, so joining stale and
fresh module output would silently produce an inconsistent result.
## 4.9 Worked Example: One Incident, End to End

To make the abstract pipeline in Sections 3-4 concrete, this section
walks a single real incident produced by the current lab run through
every stage of the reasoning layer, showing the actual intermediate
output at each step rather than a hypothetical illustration.

### 4.9.1 Raw evidence

The hybrid telemetry pipeline (Section 2) produced six `RAW_EVENT`
nodes from this lab run: one auditd event (a `pkexec` invocation with
`argc=0`), three Apache access log events, and two eBPF tracepoint
events. The Evidence Graph construction step
(`EvidenceGraph.load_from_obsidian_outputs()`) converted these into
six `RAW_EVENT` nodes plus three `INDICATOR` nodes (one per CVE in
this lab's threat-intelligence fetch).

### 4.9.2 BCA: correlation

BCA grouped the privilege-escalation-related events under the actor
key `user:1000` (the auditd `uid` field). Two of these events shared a
timestamp delta within the 300-second window and an identical
technique (`T1548.001`, repeated -- the auditd line and one of the two
eBPF tracepoints for the same underlying `pkexec` call). Because the
observed sequence `[T1548.001, T1548.001]` does not exactly or
partially match any entry in `KNOWN_CHAIN_PATTERNS` (which expects a
*different* technique to follow, not a repeat of the same one), BCA
assigned this incident the 0.40 ("multiple techniques, unrecognized
chain") confidence band -- correctly, by the algorithm's own
specification, even though a human reviewing the underlying data would
recognize both events as the same real-world action observed twice by
two different telemetry sources (auditd and eBPF). This is a genuine,
visible limitation of v1.0's single-actor, sequence-only matching
logic, surfaced here rather than in the abstract: BCA has no mechanism
to recognize that two technique-identical events from different
telemetry sources at nearly the same timestamp are corroborating
observations of one action rather than two sequential actions. We
note this not to discourage scrutiny but because identifying exactly
this kind of concrete failure mode is the purpose of walking a real
example rather than only presenting the algorithm in the abstract.

The resulting `ASSERTION` node was written into the Evidence Graph as
`assert-f67558b3`, with two `SUPPORTS` edges back to its member
`RAW_EVENT` nodes.

### 4.9.3 BCE: confidence

The Confidence Engine's second pass over the same node found four
`SUPPORTS` edges in total once correlation-engine-derived assertions
were included (`corroboration = 1 - 1/(1+4) = 0.80`), spanning two
distinct provenances -- auditd and eBPF (`source_diversity =
min(2/4, 1) = 0.50`) -- and zero `CONTRADICTS` edges
(`contradiction_penalty = 0`). Combined with BCA's own 0.40 as the
`pattern_strength` term, the resulting BCE score was approximately
0.51 -- higher than BCA's own 0.40, because corroboration from two
independent telemetry sources is a real positive signal even though
the pattern-matching component remained ambiguous. This is the concrete
case Section 4.2.1 describes in the abstract: two equally
pattern-ambiguous incidents would not necessarily receive the same BCE
score, because BCE looks at corroboration BCA cannot see from inside a
single actor's event group.

### 4.9.4 BRS: risk

The corresponding CVE, CVE-2021-4034, received a composite score of
63.5 (HIGH band) from BRS: `threat_cvss=78.0` (CVSS 7.8, rescaled),
`active_exploitation=70.0` (in KEV, ransomware use unconfirmed),
`campaign_breadth=40.0` (no known botnets for a local-privilege-
escalation CVE, as the threat-intel module's own campaign data notes),
and `defense_gap=60.0`, reported with the `untested-default` mode flag
-- meaning the Purple Team coverage file did not contain a
CVE-2021-4034-specific entry at the time this particular Evidence
Graph snapshot was built, so BRS used its documented neutral default
rather than fabricating a coverage figure (Section 4.3.1).

### 4.9.5 BTR: temporal profile

The two member events were 0.0 seconds apart (both timestamped to the
same recorded second), yielding `tempo_class = MACHINE_SPEED` and
`regularity = 1.00`. No anomalous gaps were flagged. This is the
expected, correctly classified signature of a single, instantaneous
local exploit -- not a multi-step, human-paced operation -- and matches
the real nature of the PwnKit exploit, which executes in a single
process invocation.

### 4.9.6 BAPP: structural hypothesis

Given the observed tactic sequence ending in Privilege Escalation,
BAPP proposed two structurally plausible next tactics:
`Privilege Escalation -> Credential Access` (plausibility 0.60) and
`Privilege Escalation -> Defense Evasion` (plausibility 0.55), both
marked detectable under this lab's current telemetry gap analysis.
Both were written into the graph as `HYPOTHETICAL` conclusion nodes,
explicitly not implying that either was observed.

### 4.9.7 BER: priority

Evidence Ranking computed `severity=0.40` (this incident's BCA-assigned
severity is MEDIUM), `confidence_gap=0.60` (the *inverse* of BCE's
0.40 confidence -- Section 4.6.2's deliberate inversion), `recency~=1.00`
(very recent at scoring time), and `blast_radius=0.40` (two distinct
entities touched, per the Knowledge Graph projection), yielding a
priority score of 0.559 -- the *highest* of the three incidents
produced by this lab run, ahead of the higher-severity VECTOR-I
incident (BCA severity HIGH, BCE confidence 0.95, priority 0.483).
This is the inversion's concrete effect, not just its abstract
justification: a MEDIUM-severity, lower-confidence incident outranked
a HIGH-severity, well-corroborated one for analyst attention, because
the well-corroborated incident needs comparatively little additional
human judgment to act on, while the ambiguous one does.

### 4.9.8 BDE: synthesis

The Decision Engine's join produced the following technical-briefing
entry for this incident (reproduced verbatim from
`blackwell-core/decision-engine/output/decision_items.json`):

```
Rank: 1
Priority: 0.559   Risk: HIGH (63.5)   Confidence: 0.40
Root cause: 12+ Year Latent Logic Flaw (polkit pkexec, present since 2009)
Preventive actions:
  - Regular inventory of SUID binaries + removal of unnecessary SUID bits
  - eBPF-based syscall monitoring (to close auditd's visibility gap)
  - Additional isolation for low-privilege users (e.g. seccomp profiles)
If this continues (structural hypothesis, not a forecast):
  - Privilege Escalation -> Credential Access (detectable)
  - Privilege Escalation -> Defense Evasion (detectable)
Evidence: Backed by 4 supporting evidence link(s), across 5 connected
evidence node(s) within 2 hops.
```

Every line in this entry traces to a specific upstream module's
specific computed value -- the root cause to the legacy `root-cause`
module's hand-compiled causal chain, the priority score to BER's
formula with its component values inspectable, the hypothetical next
steps to BAPP's tactic-transition lookup. The executive briefing
rendered from the same underlying object surfaces this incident as
"HIGH risk" with the first preventive action as the single recommended
line -- a shorter, plainer-language view of the identical evidence, not
a separately-authored summary that could drift from the technical
detail above it.
## 5. Evaluation

### 5.1 The constraint that shapes this section

This project has no access to real comparative data against commercial
SIEM correlation engines — Splunk Enterprise Security, Microsoft
Sentinel, or Elastic Security. No such comparison was run. We state
this before presenting any number in this section because, in our
judgment, the single most damaging thing a project like this can do is
fabricate or imply a benchmark that was never run. A fabricated number
is more dangerous than an absent one — it looks like evidence. Section
5.4 makes this an explicit, enumerated list rather than leaving it to
be inferred.

Given that constraint, we use three evaluation strategies, each chosen
because it is something this project can measure honestly at its
current scale.

### 5.2 Synthetic ground-truth precision/recall

We constructed a small (10-event), hand-labeled fixture
(`blackwell-core/benchmark/fixtures/synthetic_events.json`) in which
the correct incident boundaries are known by construction — not
because the fixture resembles production SOC alert volume (it does
not, by two to four orders of magnitude), but because it is the only
data we can build for which the "correct answer" is actually known,
which is the precondition for precision and recall to mean anything at
all.

The fixture deliberately exercises three cases chosen to stress
specific parts of BCA's logic rather than only the cases it is tuned
for:

1. **Clean two-actor separation** — two actors active in an
   overlapping time window must not be merged into one incident.
2. **A window-boundary straggler** — an event from the *same* actor
   placed just outside the default 300-second window must be split
   into a separate incident, despite sharing an actor key with the
   preceding group.
3. **An unmatched-pattern chain** (`T1071 -> T1041`, Command and
   Control followed by Exfiltration — not present in BCA's bundled
   `KNOWN_CHAIN_PATTERNS`) — exercising the 0.40-confidence "ambiguous,
   not dismissed" branch honestly, rather than testing only the
   exact-match and prefix-match cases BCA's pattern library was built
   around.

Using a strict, set-exact scoring rule (a ground-truth group counts as
correctly recovered only if BCA produces an incident whose member-event
set is *exactly* that group — no partial-overlap credit, because
BCA's job is specifically to draw correct boundaries), the current
implementation achieves precision 1.0, recall 1.0, F1 1.0 on this
fixture. We report this as a correctness check on a small adversarial
fixture, not as a production-scale performance claim, and the
benchmark framework's own README states this distinction directly.

### 5.3 Ablation study

We ran BCA twice against the same real Evidence Graph — built from
this project's own lab telemetry, not synthetic data — once with the
real `KNOWN_CHAIN_PATTERNS` library and once with an empty pattern
library. This isolates how much of BCA's behavior is attributable to
temporal/actor grouping alone versus kill-chain pattern matching
specifically.

The honest result on the current lab dataset (6 raw events, 3
resulting incidents): incident *count* was identical in both
conditions, which is expected and not informative on its own — pattern
matching happens strictly after grouping in BCA's design, so it cannot
structurally affect incident boundaries regardless of the data. Mean
confidence was *also* identical between conditions in this specific
run (0.517 in both), because none of the three incidents produced from
this particular dataset land in the 0.70 (partial match) or 0.95 (exact
match) branches of the scoring function — they fall into the 0.40 and
0.20 branches, which do not consult the pattern library at all. We
report this as the actual finding of this run rather than
manufacturing a confidence gap that this particular dataset did not
produce. A larger or differently-shaped telemetry set that exercises
the exact-match and prefix-match branches would be expected to show a
measurable gap between conditions; this ablation reports what this
specific run actually produced.

### 5.4 What we explicitly do not claim

We list these by name because, in our judgment, what a project refuses
to claim is as load-bearing as what it claims:

1. **No comparison against Splunk Enterprise Security, Microsoft
   Sentinel, or Elastic Security's correlation engines was performed.**
   None is reported. Any future claim of this kind would require
   running BCA and the comparison system against the same dataset,
   which has not been done.
2. **The synthetic fixture's perfect precision/recall is not a
   production performance claim.** It is a correctness check against
   ten hand-constructed events.
3. **The literature-referenced context table (Section 5.5) contains
   figures this project did not measure.** It is presented as outside
   context for interpreting this project's own numbers, never as a
   benchmark this project was run against.
4. **The ablation's "no measurable confidence gap" result is reported
   as-is**, not adjusted or re-run with different data chosen to
   produce a more impressive-looking gap.

### 5.5 Literature-referenced context (explicitly not a benchmark)

| Metric | Published figure | Source | Caveat |
|---|---|---|---|
| Daily alert volume, mid-to-large SOC | Commonly cited industry range: 10,000-150,000+ alerts/day, depending on organization size and tooling | Repeated widely across SOC industry analyst reports and vendor surveys | Figures vary substantially by source, methodology, and year; this is directional context, not a precise target this project was measured against. |
| Alert correlation/reduction via commercial SOAR/SIEM correlation features | Vendor marketing materials for correlation features commonly cite reduction ratios in the 60-90% range | Vendor-published product marketing and case studies (Splunk, Microsoft Sentinel, Elastic) | Vendor-reported figures on the vendor's own customer data and methodology, not independently verified, and not a comparison this project performed. This project's own measured ~50% reduction on its own six-event lab dataset (Section 4.1) is not directly comparable -- different data, different scale, different methodology. |

---

## 6. Discussion

### 6.1 What the design choices have in common

Read across Sections 3 and 4, a small number of design principles
recur deliberately rather than coincidentally:

1. **Claims are graph nodes; entities are a projection of claims, not
   the reverse.** This ordering is what makes "why do you believe
   this" a query instead of an investigation.
2. **Ambiguity is surfaced, never silently resolved.**
   `find_contradictions` flags; it does not adjudicate. The Decision
   Engine routes contradictions to a human. This is the same instinct
   applied at two different layers of the system.
3. **Confidence and urgency are kept as two separate numbers
   precisely where they would otherwise be conflated** (Section 4.6),
   because the cases where they diverge are exactly the cases that
   matter most for triage.
4. **Every hand-set weight is described as hand-set.** No module in
   this paper implies statistical calibration it does not have. We
   consider this more valuable, at this project's current stage, than
   a higher-variance claim of a learned or calibrated model the
   project cannot yet support with a labeled outcome dataset.
5. **Hypothetical and confirmed findings are never allowed to share a
   representation that could blur the distinction** — established
   first in the legacy Risk Graph module, and deliberately reused by
   BAPP rather than reinvented.

### 6.2 On the relationship between BCA/BRS and their legacy counterparts

We want to be direct about what changed and what did not, because
overstating the delta would undercut the paper's own stated
commitment to accurate claims. `correlation-engine/correlate.py` and
`risk-engine/risk_engine.py` already contained the core algorithmic
ideas — actor+window+pattern grouping, and a four-signal composite
risk formula with a self-referential defense-gap term. BCA and BRS's
contribution is formalization (explicit problem statements,
pseudocode, and stated evaluation protocols), graph integration (every
output becomes an inspectable, queryable node rather than a terminal
JSON file), and the sensitivity/ablation analysis that the original
modules did not include. Where this matters for a reader evaluating
this paper's contribution: the *algorithmic* novelty is concentrated
in the newer modules built specifically for this reasoning layer (the
Confidence Engine, Evidence Ranking, Attack Path Prediction, and the
Decision Engine's synthesis approach), not in BCA/BRS's underlying
scoring logic, which is restated rather than reinvented.

---

## 7. Limitations and Future Work

### 7.1 Limitations carried at the system level

Beyond the module-specific limitations stated in Section 4 (and, in
more detail, in each module's own README and source docstring), three
limitations apply across the whole reasoning layer:

1. **Scale.** Every algorithm here was built and evaluated against a
   lab-scale dataset (single digits to low tens of events). The data
   structures (the property-graph-shaped Evidence Graph in particular)
   were chosen to make scaling a storage-layer concern rather than a
   model rewrite, but that claim itself has not been tested against
   production-scale telemetry volume.
2. **No learned components.** Every scoring function in this paper is
   a hand-engineered, explainable formula. This is a stated, deliberate
   choice favoring auditability over the higher ceiling a learned
   model might offer — but it does mean no claim of statistical
   calibration should be inferred anywhere in this paper.
3. **Single-incident, single-snapshot reasoning.** None of the
   algorithms here reason about state across multiple Evidence Graph
   snapshots over time (e.g., "this actor's behavior changed compared
   to last week"). Each run reasons about the graph as it currently
   stands.

### 7.2 Future work

1. **Graph database migration.** The Evidence Graph's node/edge schema
   was deliberately kept property-graph-shaped specifically to make a
   migration to Neo4j or JanusGraph a storage-layer swap rather than a
   model rewrite, for deployments beyond lab scale.
2. **Learned confidence and risk components**, contingent specifically
   on acquiring a labeled outcome dataset — analyst-confirmed
   true/false-positive labels, or confirmed actual-impact outcomes —
   that does not currently exist for this project. We consider this
   the single most consequential piece of future work, and we are
   explicit that it is not attempted in this paper because the
   prerequisite data does not exist yet, not because it was
   deprioritized.
3. **Cross-snapshot temporal reasoning** — extending BTR's
   within-incident tempo analysis to cross-incident, cross-snapshot
   behavioral change detection.
4. **Entity resolution across actor keys**, to lift BCA's single-actor
   scope limitation (Section 4.1.5) toward detecting coordinated
   multi-actor campaigns.
5. **MITRE ATT&CK group/campaign-derived pattern and transition
   libraries**, replacing the current hand-curated, project-specific
   `KNOWN_CHAIN_PATTERNS` and `TACTIC_TRANSITION` tables (Sections
   4.1.5, 4.7.4) with libraries derived from MITRE's published data —
   the algorithms themselves are already generic with respect to the
   pattern library's contents; only the bundled library is
   project-specific.

---

## 8. Conclusion

This paper presented Blackwell Core, an evidence-driven reasoning
layer built on top of an existing 17-module security telemetry and
reporting platform. The central architectural claim is that alert
fatigue, detection coverage blindness, and the technical-to-executive
communication gap are symptoms of one underlying deficiency — the
absence of a shared, queryable evidence substrate — rather than three
separate point problems requiring three separate tools. We presented a
formal evidence graph model that keeps claims and entities
structurally distinct, eight reasoning algorithms that read and write
that graph with explicitly documented formulas, sensitivity profiles,
and limitations, and a synthesis layer that produces dual-audience,
fully traceable decisions from one underlying join rather than two
independently-maintained summaries.

We evaluated the system using three strategies chosen specifically
because each is measurable without fabrication at this project's
current scale — a synthetic ground-truth correctness check, a
real-data ablation study, and a literature-referenced context table —
and we stated explicitly, by name, the comparisons we did not run. We
consider that explicit non-claims list (Section 5.4) as much a
contribution of this paper as the algorithms themselves: in a domain
where benchmark fabrication is a real and recurring failure mode, the
discipline of stating what was not measured is part of the
methodology, not an afterthought appended to satisfy a reviewer.

---

## References and Source Standards

This project's threat-intelligence and detection-engineering content
draws on the following public standards and sources, consistent with
the disclaimer in the project root README:

- MITRE ATT&CK (R) (enterprise-attack matrix, techniques, and tactics)
- NIST National Vulnerability Database (NVD) API
- CISA Known Exploited Vulnerabilities (KEV) Catalog
- OASIS STIX 2.1 / TAXII 2.1 specifications
- CISA Advisory AA24-016A (cited for AndroxGh0st campaign attribution)
- Qualys Security Advisory, "PwnKit: Local Privilege Escalation
  Vulnerability Discovered in polkit's pkexec" (2022-01-25)

Vendor-published figures referenced in Section 5.5 (Splunk, Microsoft
Sentinel, Elastic Security marketing and case study materials) are
cited for interpretive context only and do not constitute a
comparative evaluation performed by this project.
## Appendix A: System Architecture Diagrams

### A.1 Evidence Graph data flow

```
                    +---------------------------------------+
                    |   OBSIDIAN PROTOCOL legacy pipeline    |
                    |  (17 modules, unchanged, standalone)   |
                    +-----------------+-----------------------+
                                      | produces
            +-------------------------+-------------------------+
            v                         v                         v
    unified_timeline.ndjson  cve_intel_output.json  correlated_incidents.json
            |                         |                         |
            +-------------------------+-------------------------+
                                      v
                  EvidenceGraph.load_from_obsidian_outputs()
                                      |
                                      v
                +-----------------------------------------+
                |      BLACKWELL EVIDENCE GRAPH (BEG)      |
                |  RAW_EVENT / INDICATOR / ASSERTION /     |
                |  CONCLUSION nodes + typed evidence edges |
                +-------------------+-----------------------+
                                    | read AND write
        +-----------+---------------+---------------+-----------+
        v           v               v               v           v
       BCA         BRS      Confidence Engine       BKG         BTR
        |           |               |               |           |
        +-----------+-------+-------+-------+-------+-----------+
                            v               v
                           BER            BAPP
                            |               |
                            +-------+-------+
                                    v
                          DECISION ENGINE (BDE)
                                    |
                      +-------------+-------------+
                      v                           v
            technical_briefing.md         executive_briefing.md
```

### A.2 Confidence vs. priority divergence (Section 4.6, 4.9.7)

```
                     HIGH CONFIDENCE          LOW CONFIDENCE
                  +---------------------+---------------------+
   HIGH SEVERITY  |   Lower priority    |   HIGHEST priority  |
                  | (well-understood,   | (severe AND         |
                  |  acted on quickly)  |  ambiguous -- needs |
                  |                     |  human judgment)    |
                  +---------------------+---------------------+
   LOW SEVERITY   |   Lowest priority   |   Moderate priority |
                  | (well-understood,   | (minor, but worth   |
                  |  low stakes)        |  a second look)      |
                  +---------------------+---------------------+
```

This is the structural reason Section 4.6.2 inverts the confidence
term: the upper-right quadrant (high severity, low confidence) is
where BER is built to direct attention first, and a naive
confidence-descending sort would instead direct attention to the
upper-left quadrant.

### A.3 Confirmed vs. hypothetical evidence (BAPP, Section 4.7)

```
   [CONFIRMED: Initial Access] --SUPPORTS--> [ASSERTION: Incident]
                                                     |
                                              DERIVED_FROM
                                                     |
                                                     v
                              [HYPOTHETICAL: Privilege Escalation -> Credential Access]
                                          (plausibility 0.60, never confused
                                           with a confirmed finding -- distinct
                                           node_type attribute, distinct color
                                           convention inherited from the legacy
                                           Risk Graph module)
```

---

## Appendix B: Implementation Inventory

All algorithms described in this paper are implemented as executable
Python modules under `blackwell-core/`, each independently runnable
and each producing real, inspectable JSON output rather than
illustrative pseudocode alone. The following table is a literal
accounting of what exists, for a reader who wants to verify claims
against source rather than prose.

| Module | File | Lines | Primary output |
|---|---|---|---|
| Evidence Graph | `evidence-graph/evidence_graph.py` | 430 | `evidence_graph.json` |
| Correlation Algorithm (BCA) | `correlation-bca/bca.py` | 359 | `bca_incidents.json` |
| Risk Score (BRS) | `risk-score-brs/brs.py` | 320 | `brs_scores.json` |
| Confidence Engine | `confidence-engine/confidence_engine.py` | 213 | `confidence_scores.json` |
| Knowledge Graph | `knowledge-graph/knowledge_graph.py` | 207 | `knowledge_graph.json` |
| Temporal Reasoning | `temporal-reasoning/temporal_reasoning.py` | 258 | `temporal_profiles.json` |
| Evidence Ranking | `evidence-ranking/evidence_ranking.py` | 234 | `ranked_findings.json` |
| Attack Path Prediction | `attack-path-prediction/attack_path_prediction.py` | 262 | `attack_path_predictions.json` |
| Decision Engine | `decision-engine/decision_engine.py` | 367 | `decision_items.json`, two briefings |
| Validation Framework | `benchmark/run_benchmark.py` | 345 | `benchmark_report.json` |

Total: approximately 2,995 lines of executable Python across the
Blackwell Core reasoning layer, exclusive of the underlying 17-module
OBSIDIAN PROTOCOL pipeline this layer reads from.

Every module above:

1. Runs standalone from the command line (`python3 <module>.py`) and
   produces real output from whatever upstream data currently exists,
   rather than requiring the full pipeline to be present.
2. States its own known limitations in its module-level docstring at
   the point the algorithm is defined, not in a separate document.
3. Is also documented in a per-module `README.md` summarizing the
   same content for a reader who prefers prose to source comments.
4. Was executed end-to-end against this project's own real lab data as
   part of producing the worked example in Section 4.9 and the
   evaluation results in Section 5 -- every number quoted in this paper
   is reproducible by re-running the pipeline described in the project
   root `README.md` followed by the nine Blackwell Core modules in the
   dependency order given in `blackwell-core/README.md`.

## Appendix C: Reproducing This Paper's Results

```bash
# 1. Generate the underlying OBSIDIAN PROTOCOL telemetry/correlation/
#    risk data this paper's worked example and evaluation are built on
#    (requires the lab range; see project root README.md):
./setup.sh
python3 telemetry/build_timeline.py --live
python3 correlation-engine/correlate.py
python3 threat-intel/fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034
python3 purple-team/validate.py purple-team/attack_log_template.json
python3 risk-engine/risk_engine.py
python3 root-cause/root_cause.py

# 2. Run the Blackwell Core reasoning layer, in dependency order:
python3 blackwell-core/evidence-graph/evidence_graph.py
python3 blackwell-core/correlation-bca/bca.py
python3 blackwell-core/risk-score-brs/brs.py
python3 blackwell-core/confidence-engine/confidence_engine.py
python3 blackwell-core/knowledge-graph/knowledge_graph.py
python3 blackwell-core/temporal-reasoning/temporal_reasoning.py
python3 blackwell-core/evidence-ranking/evidence_ranking.py
python3 blackwell-core/attack-path-prediction/attack_path_prediction.py
python3 blackwell-core/decision-engine/decision_engine.py

# 3. Reproduce Section 5's evaluation numbers directly:
python3 blackwell-core/benchmark/run_benchmark.py
```

Or, equivalently, the single orchestrator that runs every step above
plus the legacy reporting layer:

```bash
python3 reporting/generate_all_reports.py
```

All output paths are listed in each module's own README and in the
project root `README.md`'s directory structure section.
