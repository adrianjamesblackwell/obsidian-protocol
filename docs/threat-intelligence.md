# SIGINT MODULE — Threat Intelligence Analysis
### OBSIDIAN PROTOCOL / Who Actually Uses These CVEs, and How

> This section is an analysis built **on top of** the NVD/KEV data
> pulled by `threat-intel/fetch_cve_intel.py` — instead of just saying
> "the CVSS score is X," it answers "who, when, in which sector"
> using real campaign data. Every finding is drawn from public, named
> sources (CISA, FBI, Imperva Threat Research).

---

## 1. CVE-2021-41773 / CVE-2021-42013 — Real Campaign Data

### Official status (CISA KEV)

CISA both added this vulnerability to the KEV catalog and left a
specific note in its advisory: because the original CVE-2021-41773
patch was insufficient, the real fix needs to be sought in
CVE-2021-42013. CISA also lists this CVE among **the vulnerabilities
most frequently exploited by Chinese state-sponsored threat actors** —
meaning this isn't just an "old CVE," it's a tool still used even by
state-sponsored actors.

### AndroxGh0st Botnet — Joint FBI/CISA Advisory (AA24-016A)

In January 2024, the FBI and CISA published a joint advisory
(AA24-016A) on a botnet called AndroxGh0st. This botnet:

- Is **Python-based**, first identified by Lacework in December 2022
- Scans websites running the Laravel framework, attempting to steal
  credentials for services such as AWS, Microsoft 365, SendGrid, and
  Twilio from their `.env` files
- **Directly uses CVE-2021-41773**: it scans servers running Apache
  2.4.49/2.4.50, attempting to escape the directory root via path
  traversal to reach sensitive files
- Also uses **CVE-2017-9841** (PHPUnit RCE) and **CVE-2018-15133**
  (Laravel deserialization) in the same chain — meaning this botnet,
  too, doesn't rely on a single CVE; it uses a **chain**, much like
  the one built in this lab

### Sector Targeting — Concrete Numbers (Imperva Threat Research, 2024)

Imperva's 2024 data shows that attacks attempting to exploit these
CVEs (and the related PHPUnit/Laravel vulnerabilities) targeted
**more than 30,000 unique sites**, concentrated **predominantly in
the Financial Services and Business sectors**.

The practical implication: this vulnerability isn't "random internet
scanning" — attackers are **specifically** selecting targets running
Laravel that likely hold valuable API keys (AWS, payment services).

### An Additional Imperva Finding — Chain Expansion

Imperva also found an unexpected vulnerability (Drupal Core
CVE-2019-6340) being used in the same campaign, with the same proxy
IPs deploying the same web shell within similar time windows — meaning
these actors expand their chain **by adding new CVEs over time**,
rather than staying static.

### Malware Payloads

In its early period, this CVE was used to distribute the **Linuxsys
cryptomining software**. In the AndroxGh0st campaign, it was observed
being used more for credential theft and **XMRig cryptominer**
distribution.

---

## 2. CVE-2021-4034 (PwnKit) — A 13-Year Hidden Vulnerability

### Timeline

| Date | Event |
|---|---|
| May 2009 | The vulnerable code enters polkit's first public release |
| January 25, 2022 | Qualys publicly discloses the vulnerability (12+ years later) |
| January 27, 2022 | The first public exploit PoCs begin to spread |
| June 27, 2022 | CISA adds it to the KEV catalog |
| July 18, 2022 | Mandatory remediation deadline for federal agencies |

### Why It Still Matters (a 2026 Perspective)

PwnKit's CVSS score is 7.8 — high but not critical. Yet independent
of the score itself: this vulnerability affected **every major Linux
distribution** and requires **no special conditions** (no network
access, no special configuration, no user interaction). Qualys also
noted that this `argc=0`-handling logic flaw in `pkexec` could
represent a vulnerability class that may recur **in similar SUID
binaries** — meaning PwnKit isn't an isolated incident, it's an
example of a pattern.

### The Real-World Role of Local Privilege Escalation

PwnKit cannot be remotely exploited on its own (local-only). This is
why, in real attack chains, it always comes **after** an initial
"get in first" step — exactly the scenario this lab simulates: RCE
from the external surface (Apache) → local foothold → root via
PwnKit.

---

## 3. Comparing This Against Your Own Lab Experience

Take the NVD/KEV data you obtain by running
`threat-intel/fetch_cve_intel.py` and put it side by side with the
real campaign data above, then answer the questions in
`docs/analysis.md`. In particular, consider:

**Does the number of minutes it took you to exploit this in the lab
explain why 30,000 real-world sites are still being scanned?** (Hint:
think about the relationship between difficulty level and scale —
is a vulnerability still being exploited because it's "easy," or
because "the number of unpatched systems is large"? Those are two
different things.)

---

## Sources

- CISA AA24-016A: [Known Indicators of Compromise Associated with Androxgh0st Malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a)
- CISA KEV Catalog: [Apache HTTP Server Path Traversal Vulnerability](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Imperva Threat Research: AndroxGh0st Botnet IOC Analysis (2024)
- Qualys Security Advisory: PwnKit (CVE-2021-4034), January 25, 2022
- Red Hat Product Security: PwnKit Response Timeline
