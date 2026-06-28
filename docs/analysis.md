# OBSIDIAN PROTOCOL — Operator Assessment
### Comparing Real Threat Data Against Operation Experience

> Before filling out this file, read
> [`docs/threat-intelligence.md`](threat-intelligence.md) — it
> contains real data such as the AndroxGh0st botnet campaign, the
> sectors it targeted, and PwnKit's 13-year timeline.

## 1. Real Data Findings (from threat-intel/cve_intel_output.json)

| CVE | CVSS Score | In KEV? | KEV Added Date | Known Botnet | 2024 Target Sector |
|---|---|---|---|---|---|
| CVE-2021-41773 | | | | | |
| CVE-2021-42013 | | | | | |
| CVE-2021-4034 | | | | | |

_(Fill this table in with real data after running `fetch_cve_intel.py`.)_

## 2. Official Risk Assessment vs. Practical Experience

**Question 1:** Does the CVSS score line up with how difficult your
exploitation experience actually was? Did a critical/high-scored
vulnerability feel genuinely "critical" in difficulty, or was it
easier/harder than you expected?

_(your answer)_

**Question 2:** How does the KEV catalog's "additive" (never-deleted)
structure explain why CVEs discovered in 2021 still pose a threat in
2026? Did your own lab experience concretely show why an old CVE
remains an "easy target"?

_(your answer)_

**Question 3:** Why does combining both halves of this CVE chain
(rather than just RCE alone, or just priv-esc alone) represent a more
realistic real-world attack scenario?

_(your answer)_

**Question 4:** We know the AndroxGh0st botnet targeted the Financial
Services and Business sectors with 30,000+ sites in 2024. Considering
how "easy" or "hard" this chain felt in your own lab experience, which
factor better explains a campaign at this scale — **the
vulnerability's ease of exploitation**, or **the sheer number of
unpatched systems**? Discuss the difference between the two, grounded
in your own experience.

_(your answer)_

## 3. Defensive Takeaways

Three concrete measures you'd take from this lab to prevent this
chain in a real environment:

1.
2.
3.
