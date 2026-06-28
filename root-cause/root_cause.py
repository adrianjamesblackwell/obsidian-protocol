#!/usr/bin/env python3
"""
root-cause/root_cause.py

OBSIDIAN PROTOCOL — Root Cause Discovery Engine

REAL-WORLD PROBLEM: Most security tools say "we found this IOC" but
never answer "WHY did this happen." Finding an IOC detects a symptom;
root cause analysis surfaces the structural reason underneath it.

SOLUTION: This module maps each CVE/technique in this project's own
attack chain to a known "primary cause -> root cause chain" and
produces the structured answer the Decision Engine's "Why?" question
needs.
"""

import json
import os
from dataclasses import dataclass, asdict

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

ROOT_CAUSE_CHAINS = {
    "CVE-2021-41773": {
        "primary_cause": "Outdated Apache HTTP Server (2.4.49)",
        "chain": [
            "Outdated Apache (2.4.49, vulnerable version released October 2021)",
            "Weak Patch Policy (the new release was not tested and patched promptly)",
            "Missing Configuration Hardening (the 'Require all denied' default was relaxed)",
            "No WAF (the path traversal pattern was not filtered at the network layer)",
        ],
        "preventive_actions": [
            "Automated patch management (e.g. unattended-upgrades + a staging test pipeline)",
            "Enforce a 'deny all' default policy in Apache configuration",
            "WAF rule: block encoded path traversal patterns (%2e%2e/, double-encoding)",
        ],
    },
    "CVE-2021-42013": {
        "primary_cause": "Incomplete Initial Patch (incomplete fix of CVE-2021-41773)",
        "chain": [
            "The first patch (CVE-2021-41773) only addressed single-level encoding",
            "The double-encoding scenario was left outside test coverage",
            "Weak Regression Testing (different encoding variants were not retested after the patch)",
            "mod_cgi left needlessly enabled (made the jump to RCE possible)",
        ],
        "preventive_actions": [
            "Add 'known bypass techniques' to the regression test matrix for security patches",
            "Keep high-risk modules like mod_cgi enabled only when genuinely required",
        ],
    },
    "CVE-2021-4034": {
        "primary_cause": "12+ Year Latent Logic Flaw (polkit pkexec, present since 2009)",
        "chain": [
            "polkit pkexec never handling the argc=0 case (a design flaw present since 2009)",
            "No EDR (no memory/syscall-level anomaly detection)",
            "Missing Segmentation (a user with a foothold can reach SUID binaries directly)",
            "auditd unable to catch the exploit ahead of pkexec's own audit code (a visibility gap)",
        ],
        "preventive_actions": [
            "Regular inventory of SUID binaries + removal of unnecessary SUID bits",
            "eBPF-based syscall monitoring (to close auditd's visibility gap — see the WARDEN module)",
            "Additional isolation for low-privilege users (e.g. seccomp profiles)",
        ],
    },
}


@dataclass
class RootCauseReport:
    cve: str
    primary_cause: str
    causal_chain: list
    preventive_actions: list


def discover_root_causes(cves: list) -> list:
    reports = []
    for cve in cves:
        data = ROOT_CAUSE_CHAINS.get(cve)
        if not data:
            continue
        reports.append(RootCauseReport(
            cve=cve,
            primary_cause=data["primary_cause"],
            causal_chain=data["chain"],
            preventive_actions=data["preventive_actions"],
        ))
    return reports


def print_report(reports: list):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — ROOT CAUSE DISCOVERY")
    print("=" * 70)
    for r in reports:
        print(f"\n{'-' * 60}")
        print(f"  CVE: {r.cve}")
        print(f"  Primary Cause: {r.primary_cause}")
        print(f"{'-' * 60}")
        print("\n  Causal Chain:")
        for step in r.causal_chain:
            print(f"    -> {step}")
        print("\n  Preventive Actions:")
        for action in r.preventive_actions:
            print(f"    * {action}")


def main():
    cves = list(ROOT_CAUSE_CHAINS.keys())
    reports = discover_root_causes(cves)
    print_report(reports)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "root_cause_report.json")
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in reports], f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {out_path}")


if __name__ == "__main__":
    main()
