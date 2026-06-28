# ROOT CAUSE DISCOVERY
### OBSIDIAN PROTOCOL / The Difference Between "Finding an IOC" and "Understanding Why"

## Problem

Most security tools say "we found this IOC" but never answer "why did
this happen." An IOC is a symptom; root cause is the structural
reason underneath it.

## Solution

`root_cause.py` provides a hand-compiled **causal chain** for each
CVE — a sequence moving from the surface technical cause toward the
organizational/process cause (e.g. "Outdated Apache" -> "Weak Patch
Policy" -> "Missing Hardening" -> "No WAF").

Each chain ends with **preventive actions** — not a reactive
suggestion like "block this IP," but a structural one like "change
this process."

## Usage

```bash
python3 root-cause/root_cause.py
```

## Known limitation

The causal chains are currently **hand-compiled** (the
`ROOT_CAUSE_CHAINS` dict) — not an automated root-cause inference
engine. In a real production system this would be derived
automatically from log correlation. This project keeps it
deliberately simple/manual because the goal was a **correct and
deep** analysis for both CVEs — judged more valuable than an automated
but shallow inference engine.

This is the reference implementation. See
[`blackwell-core/decision-engine/README.md`](../blackwell-core/decision-engine/README.md)
for how this module's output is joined with risk scoring, confidence,
and attack-path hypotheses into a single prioritized decision.
