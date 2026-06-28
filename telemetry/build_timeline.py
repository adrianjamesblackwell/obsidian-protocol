#!/usr/bin/env python3
"""
telemetry/build_timeline.py

OBSIDIAN PROTOCOL — Telemetry Pipeline Orchestrator

This script runs in HYBRID mode:
  - OFFLINE MODE: reads real log files you produced while following the
    walkthrough (auditd, Apache access log, eBPF JSON output)
  - LIVE MODE: when run with the --live flag, pulls live logs directly
    from the target-49 container via `docker exec`

Output: a single unified, time-sorted NDJSON file
(telemetry/output/unified_timeline.ndjson) — read by the Purple Team
validation layer, the Risk Engine, and the reporting engine.

Usage:
    # Offline (from previously collected logs):
    python3 build_timeline.py \\
        --auditd telemetry/sample-data/sample_auditd.log \\
        --apache telemetry/sample-data/sample_apache_access.log \\
        --ebpf telemetry/sample-data/sample_ebpf_output.jsonl

    # Live (pulls directly from the target-49 container):
    python3 build_timeline.py --live
"""

import argparse
import os
import sys
import subprocess
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "schemas"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "parsers"))

from event_schema import ObsidianEvent, write_events_ndjson
from auditd_parser import parse_auditd_log
from apache_log_parser import parse_apache_log
from ebpf_parser import parse_ebpf_stream

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
UNIFIED_TIMELINE_PATH = os.path.join(OUTPUT_DIR, "unified_timeline.ndjson")


def fetch_live_auditd(container_name: str = "obsidian-target-49") -> str:
    """
    Pulls auditd logs from the live container and writes them to a
    temp file. Uses `docker exec` — the container must be running and
    auditd must be installed (see detection/README.md setup steps).
    """
    tmp_path = "/tmp/obsidian_live_auditd.log"
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "ausearch", "-k", "pkexec_exec", "--format", "raw"],
            capture_output=True, text=True, timeout=15,
        )
        with open(tmp_path, "w") as f:
            f.write(result.stdout)
        return tmp_path
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"[!] Live auditd fetch failed: {e}")
        print("[!] Check whether auditd is installed/configured (detection/README.md).")
        return None


def fetch_live_apache_log(container_name: str = "obsidian-target-49") -> str:
    """Pulls the Apache access log from the live container."""
    tmp_path = "/tmp/obsidian_live_apache.log"
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", "/usr/local/apache2/logs/access_log"],
            capture_output=True, text=True, timeout=15,
        )
        with open(tmp_path, "w") as f:
            f.write(result.stdout)
        return tmp_path
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"[!] Live Apache log fetch failed: {e}")
        return None


def build_timeline(auditd_path=None, apache_path=None, ebpf_path=None) -> list:
    """Merges events from all sources and sorts them chronologically."""
    all_events = []

    if auditd_path and os.path.exists(auditd_path):
        auditd_events = parse_auditd_log(auditd_path)
        print(f"[+] auditd: {len(auditd_events)} event(s)")
        all_events.extend(auditd_events)

    if apache_path and os.path.exists(apache_path):
        apache_events = parse_apache_log(apache_path)
        print(f"[+] Apache access log: {len(apache_events)} event(s)")
        all_events.extend(apache_events)

    if ebpf_path and os.path.exists(ebpf_path):
        ebpf_events = parse_ebpf_stream(ebpf_path)
        print(f"[+] eBPF: {len(ebpf_events)} event(s)")
        all_events.extend(ebpf_events)

    # Sort chronologically — required so the Purple Team module can
    # compute "attack step happened at time X, detection arrived at
    # time Y, latency Z."
    all_events.sort(key=lambda e: e.timestamp)
    return all_events


def main():
    parser = argparse.ArgumentParser(description="OBSIDIAN PROTOCOL Telemetry Pipeline")
    parser.add_argument("--auditd", help="Path to the auditd log file")
    parser.add_argument("--apache", help="Path to the Apache access log file")
    parser.add_argument("--ebpf", help="Path to the eBPF JSON output file")
    parser.add_argument("--live", action="store_true", help="Pull live from the target-49 container")
    parser.add_argument("--container", default="obsidian-target-49", help="Target container name for live mode")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    auditd_path, apache_path, ebpf_path = args.auditd, args.apache, args.ebpf

    if args.live:
        print(f"[*] LIVE MODE: pulling telemetry from the {args.container} container...")
        auditd_path = fetch_live_auditd(args.container) or auditd_path
        apache_path = fetch_live_apache_log(args.container) or apache_path

    if not any([auditd_path, apache_path, ebpf_path]):
        print("[!] You must specify at least one source (--auditd, --apache, --ebpf, or --live).")
        sys.exit(1)

    print("[*] Building unified timeline...")
    events = build_timeline(auditd_path, apache_path, ebpf_path)

    # Clean up any file left over from a previous run (write_events_ndjson
    # is append-safe, so remove first to guarantee a clean start)
    if os.path.exists(UNIFIED_TIMELINE_PATH):
        os.remove(UNIFIED_TIMELINE_PATH)
    write_events_ndjson(events, UNIFIED_TIMELINE_PATH)

    print(f"\n[+] {len(events)} total event(s) merged.")
    print(f"[+] Output: {UNIFIED_TIMELINE_PATH}")

    detection_count = sum(1 for e in events if e.is_detection_signal)
    print(f"[+] {detection_count} event(s) matched a VECTOR/CVE signal.")


if __name__ == "__main__":
    main()
