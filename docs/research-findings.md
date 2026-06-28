# RESEARCH FINDINGS
### OBSIDIAN PROTOCOL / Metrics, Limitations, Findings

> This document exists to move the project beyond "it works" and
> into "here's what I learned, what I measured, and where I know it
> stands." Written in an academic-report format: measurable metrics,
> deliberately out-of-scope points, a performance comparison, and
> lessons learned.

---

## 1. Measurable Metrics

The numbers below are **real outputs** produced from the system's own
sample dataset (`telemetry/sample-data/`,
`purple-team/attack_log_template.json`) — none of them are estimates
or target values.

| Metric | Value | Source |
|---|---|---|
| Total Python lines of code | 4,705 | `find . -name "*.py" \| xargs wc -l` |
| Total module count | 17 | top-level directory count |
| Sigma rule count | 2 (VECTOR-I, VECTOR-II) | `detection/sigma/` |
| YARA rule count | 2 | `detection/yara/pwnkit_artifacts.yar` |
| STIX 2.1 objects | 18 (3 vulnerability, 3 attack-pattern, 3 indicator, 1 malware, 8 relationship) | `intel-export/stix_export.py` output |
| Telemetry events (sample run) | 6 (from 3 sources: auditd, Apache log, eBPF) | `telemetry/output/unified_timeline.ndjson` |
| Correlation Engine alert reduction (sample run) | 50% (6 raw events → 3 incidents) | `correlation-engine/correlate.py` output |
| Detection Coverage (sample run) | 75% (3/4 attack steps) | `purple-team/output/coverage_results.json` |
| Coverage Heatmap (over the known technique subset) | 43% (3/7 techniques validated) | `coverage-heatmap/heatmap.py` output |
| Average detection latency (sample run) | 0.0–5.0s range (varies by run) | `purple-team/validate.py` output |
| Risk score range (sample run) | 48.5–60.5 / 100 | `risk-engine/output/risk_scores.json` |
| Emulation Score - Attack Diversity (sample run) | 42.9% (3 unique techniques) | `emulation-score/emulation_score.py` output |
| Emulation Score - MITRE Matrix Coverage | 1.39% (over all 216 techniques) | same source; note: expected/normal to be low |
| Rule Quality - rules analyzed | 2 (both graded "good condition") | `rule-quality/analyze_rules.py` output |
| IOC Decay - IOCs tracked | 3 (2 ACTIVE, 1 AGING) | `ioc-decay/ioc_decay.py` output |
| Telemetry Gap - blind tactic count | 6/11 (Collection, C2, Credential Access, Discovery, Exfiltration, Lateral Movement) | `telemetry-gap/gap_analysis.py` output |

### What These Numbers Are, and What They Aren't

**Important methodological note:** the Coverage/Latency/Risk numbers
above were produced from a small **sample/demo dataset** (4 attack
steps, 3 telemetry sources) — this is not a statistically
representative sample of a production-scale SOC environment. The
system's purpose isn't the claim "I currently provide 50% coverage,"
it's **building a methodology that measures and computes coverage
correctly**. In a real operation (with `docs/walkthrough.md` fully
executed), these numbers will change; what matters is that the
measurement infrastructure works correctly.

### False Positive Rate — Why It Can't Be Measured (Yet)

A deliberate transparency note: this project does **not** compute a
false positive rate, because a statistically meaningful measurement
of that requires a "background noise" generator producing benign/
normal traffic (e.g. real-world noise such as cron jobs, legitimate
user traffic, system maintenance commands). This project only
simulates the attack scenario; measuring FP rate would require a
separate "benign traffic generator" module (see Section 3, Future
Work #4).

---

## 2. Limitations (Deliberately Out-of-Scope Points)

This section exists to demonstrate the difference between "not
knowing what wasn't done" and "consciously deciding what not to do."

| # | Limitation | Why It's Deliberate |
|---|---|---|
| 1 | The Purple Team matching algorithm works only off the VECTOR+CVE tag, with no network/process/parent-child relationship correlation | A production SIEM correlation engine is out of scope; the goal is to demonstrate the methodology, not build a production-grade correlation engine |
| 2 | Risk Engine weights (0.25/0.30/0.20/0.25) are fixed and hand-set, not probabilistic/ML-based like EPSS | Transparency was prioritized — each component's contribution to the score is individually visible, not a black-box model |
| 3 | The TAXII server supports read only (GET /objects/), with no write/filtering/authentication | Intended as a reference implementation; production TAXII servers like OpenCTI/EclecticIQ have a much broader scope |
| 4 | The eBPF collector (`pwnkit_ebpf_trace.bt`) needs system boot time for a real timestamp, and currently uses a placeholder | Injecting `/proc/uptime` inside the container requires an extra setup step, deliberately left out of scope |
| 5 | Only 2 CVEs / 2 attack vectors are covered | Depth was prioritized over breadth — fully processing 2 CVEs through their entire lifecycle (recon->report) was judged more valuable than superficially covering 10 |
| 6 | Recon steps (e.g. a bare GET /) have no detection signature of their own and are flagged as "missed" | This is not a bug, it's a genuine observability limit — in real SOCs too, recon traffic generally can't be separated from noise (see Section 5) |
| 7 | The time window between the Risk Engine and Purple Team (default 120s) is fixed, not adaptive | Kept simple and explainable on purpose; in a real system this window should vary by CVE type (e.g. local priv-esc vs. network-based) |
| 8 | There is a single target system (TARGET-49), with no lateral movement / multi-host scenario | Scope was focused on one realistic chain (external->internal->root); a multi-host scenario is in Future Work |
| 9 | The Correlation Engine's `KNOWN_CHAIN_PATTERNS` only knows this project's own VECTOR-I/II chain, and isn't derived from real APT group TTP datasets | In production this could be auto-derived from MITRE's official campaign/group STIX data (Future Work #8) |
| 10 | The Emulation Score is computed from only 3 incidents / 3 unique techniques — a statistically small sample | This is proportional to this project's scope (2 CVEs); the score itself transparently carries a "small sample" note |
| 11 | Root Cause Discovery's causal chains (`causal_chain`) were written manually/from expert knowledge, not derived from automated log analysis | A real "automated root cause" system is its own separate research area (causal inference from log correlation); this module demonstrates the "format and presentation" |

---

## 3. Future Work

A prioritized, realistic list of next steps:

1. **Adaptive risk weighting** — instead of the fixed weights
   (Section 2, #2), a simple feedback mechanism that self-adjusts
   based on historical coverage results (e.g. automatically
   increasing the `defense_gap` weight for CVEs that keep getting
   missed).
2. **Multi-host / lateral movement scenario** — adding a second
   internal-network host alongside TARGET-49, and chaining a
   post-PwnKit lateral movement step (e.g. SSH key reuse, internal
   service discovery) onto the attack.
3. **Real-time eBPF dashboard** — connecting the eBPF parser, which
   currently runs in batch/offline mode, to a live terminal dashboard
   (e.g. using the `rich` or `textual` library).
4. **Benign traffic generator** — a background generator producing
   legitimate/harmless traffic, to make the false-positive rate
   measurable (closing the FP measurement gap from Section 1).
5. **STIX Sighting objects** — currently only Indicator/Vulnerability/
   Malware objects are produced; converting each real detection event
   into a STIX `sighting` object would make "how many times was this
   indicator observed" answerable in STIX format.
6. **CALDERA/Atomic Red Team integration** — automated, repeatable
   attack emulation via MITRE CALDERA instead of manual exploit
   scripts (especially valuable for multi-run statistical coverage
   measurement).
7. **A third vector (VECTOR-III)** — adding a different vulnerability
   class (e.g. deserialization or SSRF) and observing how the Risk
   Engine behaves across different CVE profiles.
8. **Automated kill-chain derivation from MITRE Group/Campaign data**
   — deriving the Correlation Engine's `KNOWN_CHAIN_PATTERNS`
   automatically from MITRE's official STIX campaign/intrusion-set
   dataset (known TTP sequences of real APT groups), instead of
   hand-defining them.

---

## 4. Performance Comparison: auditd vs. eBPF

Since this project uses both (hybrid), it's worth comparing their
cost/benefit tradeoff against real, cited figures from the
literature:

| Dimension | auditd | eBPF |
|---|---|---|
| CPU overhead | Typically reported in the 5-15% range for conventional userspace audit agents | Typically under 1%; measurements in container/VM environments stay below 2% |
| Behavior at high event volume | At tens of thousands of syscalls per second, there's a risk of performance degradation from audit buffer overflow or synchronous disk-write load | Because events are filtered and aggregated inside the kernel, it holds up better under high volume |
| Visibility level | Via the userspace audit subsystem; can be delayed/incomplete for some syscalls | Directly at the kernel tracepoint/kprobe level, at the moment of the syscall |
| Setup complexity | Pre-installed on most distributions, simple configuration via audit.rules | Requires additional tooling (bpftrace/BCC) plus CAP_BPF/CAP_SYS_ADMIN capabilities |
| The PwnKit (VECTOR-II) special case | May catch nothing at all in some variants, because the exploit runs ahead of pkexec's audit/logging code (see detection/README.md) | Can close this gap because it sees the syscall directly from the kernel |

**Sources:** the CPU overhead figures are based on general literature
observations (eBPF performance analysis writeups, 2025-2026; the
eBPF-PATROL academic evaluation, reporting sub-2% CPU overhead in
container/VM environments); auditd's buffer-overflow behavior under
high-volume scenarios is a documented observation from a GPU cluster
security-monitoring context (a Backend.AI eBPF security audit
writeup, 2026). These figures have not been separately benchmarked in
OBSIDIAN PROTOCOL's own environment — that is a next step that has
been added to the Future Work list.

**The practical conclusion in this project:** the rationale for the
hybrid approach is exactly the last row of this table — there's a
class of attack auditd "can't see" (PwnKit's audit-bypassing nature),
and eBPF closes that gap. This is an **architectural** answer to
"why two layers," not an experimental one.

---

## 5. Lessons Learned / Research Findings

Three findings that emerged during development and weren't planned
from the start:

### Finding 1: "Recon steps are structurally blind from an observability standpoint"

While testing the Purple Team module, it became clear that the recon
step (a bare `GET /` request) never matched any detection signal. At
first glance this looked like a bug, but root-cause analysis showed
it's **correct behavior**: a request that looks benign should, by
definition, never trigger any signature. This was a small-scale
reflection of a problem real SOC environments also face — traffic
with a "low signal-to-noise ratio" (recon, scanning) cannot be caught
by signature-based systems; that is a structural limitation requiring
behavioral/statistical anomaly detection (deliberately out of this
project's scope, see Section 2, #6).

### Finding 2: "The same CVSS score can mean different real-world risk"

Running the Risk Engine produced an unexpected result: CVE-2021-4034
(PwnKit, CVSS 7.8) received a higher composite risk score than
CVE-2021-42013 (CVSS 9.8, higher) — 73.5 vs. 60.5. The reason was that
PwnKit's detection coverage was **0% in the sample run**
(the `defense_gap` component maxed out). This proved the formula was
working as intended, confirming the original design hypothesis (CVSS
alone is not a sufficient prioritization signal) — but it also
revealed something else: **composite risk-scoring formulas can be
overly sensitive to the quality of their own input data.** Because
coverage came out at 0% in a single test run, PwnKit was labeled
"high risk"; in a real operation, this could have produced a false
prioritization if the coverage measurement itself were unreliable.
Lesson: in composite scoring systems, each component's **own
reliability** also needs to be assessed separately (e.g. a warning
like "only 1 attack step was tested for this CVE" should be added —
now in Future Work).

### Finding 3: "Conforming to a format specification can be more portable than depending on a library"

The decision to produce the STIX 2.1 and TAXII 2.1 modules using raw
JSON/HTTP instead of the `stix2`/`taxii2-client` libraries started as
a constraint (the library couldn't be installed without network
access), but turned out to be an advantage: the resulting output runs
independently of any Python version/library version conflict, and
exactly "what's underneath the spec" stays directly readable. This
supports a real engineering principle: **a dependency is sometimes
more expensive than the abstraction it provides** — especially when
the format is already a well-documented standard.

### Finding 4: "The same actor identity can be incorrectly split apart when it comes from different timestamp sources"

While developing the Correlation Engine, events originating from eBPF
(`user:1000`) and events originating from auditd (`user:1000`) — despite
sharing the **same actor identity** — were grouped into separate
incidents. Root cause: the eBPF parser currently uses the collector's
own execution timestamp instead of a real syscall timestamp (see
Section 2, #4), while auditd carries the event's actual epoch time.
When two sources use different "time reference frames," even a
correct correlation engine can mis-split events.

At first this looked like a bug, but closer inspection showed:
**a correlation engine's accuracy depends on the time-synchronization
quality of its own input data.** This is a small-scale reflection of
a well-known problem (clock skew) seen in real distributed systems
with weak NTP synchronization. Lesson: when evaluating a correlation/
SIEM engine, it's not just the algorithm's logic that needs auditing —
**the time consistency of the data sources feeding it** must be
audited too, or the result is "correct algorithm, wrong data."

---

## Closing Note

This document was written to let OBSIDIAN PROTOCOL say not "it's
done," but "here is its current state, here's why, and here's the
next step." Being able to clearly state a system's limitations is an
engineering skill distinct from — and equally valuable as — building
the system itself.
