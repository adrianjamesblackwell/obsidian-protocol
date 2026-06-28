#!/usr/bin/env python3
"""
purple-team/validate.py

OBSIDIAN PROTOCOL — Purple Team Validation Layer

This module automates the "attack -> detection -> validation" loop:

  1. GROUND TRUTH: scripts/attack_log.json, the file where the
     operator (you) records when each attack step was actually
     performed (filled in manually or semi-automatically — see
     attack_log_template.json)
  2. DETECTION SIGNALS: events with is_detection_signal=true in
     telemetry/output/unified_timeline.ndjson (signals WARDEN caught
     via Sigma/auditd/eBPF)
  3. MATCHING: for each ground-truth attack step, looks for a
     detection signal with the same VECTOR/CVE label within a time
     window (default +/-120s)

Output: a Detection Coverage report -- which attack step was caught,
which was missed (false negative), and average detection latency (a
simplified version of MTTD).

This is a small-scale automated version of what real purple team
operations do: matching the red team's actions against what the blue
team actually saw, and measuring the gap.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional

TELEMETRY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "telemetry", "output", "unified_timeline.ndjson"
)
DEFAULT_MATCH_WINDOW_SECONDS = 120


@dataclass
class CoverageResult:
    attack_step: str
    vector: str
    cve: str
    mitre_technique: str
    attack_timestamp: str
    detected: bool
    detection_timestamp: Optional[str] = None
    detection_source: Optional[str] = None
    detection_latency_seconds: Optional[float] = None
    matched_event_id: Optional[str] = None


def load_ground_truth(path: str) -> list:
    """Loads the operator's attack_log.json file."""
    with open(path) as f:
        return json.load(f)


def load_telemetry_events(path: str) -> list:
    """Loads the unified telemetry timeline."""
    if not os.path.exists(path):
        print(f"[!] Telemetry file not found: {path}")
        print("[!] Run telemetry/build_timeline.py first.")
        return []
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def find_matching_detection(attack_step: dict, telemetry_events: list, window_seconds: int) -> Optional[dict]:
    """
    For one attack step, looks for a detection signal with the same
    vector AND cve label, within the time window (AFTER the attack
    moment, since detection can't come before the attack).

    NOTE -- known limitation: some recon/discovery steps may have no
    detection signal of their own (e.g. a plain GET / request doesn't
    trigger any Sigma rule). In that case no match is found and the
    step is marked "MISSED" -- this is NOT WRONG, because there
    genuinely is no step-specific detection signal. When interpreting
    the coverage report, keep in mind that some "missed" steps may
    simply be recon steps that carry no detectable signature in the
    first place.
    """
    attack_time = parse_iso(attack_step["timestamp"])
    candidates = []

    for ev in telemetry_events:
        if not ev.get("is_detection_signal"):
            continue
        if ev.get("vector") != attack_step.get("vector"):
            continue
        if ev.get("cve") != attack_step.get("cve"):
            continue

        ev_time = parse_iso(ev["timestamp"])
        delta = (ev_time - attack_time).total_seconds()

        # Detection can't precede the attack (a small tolerance for
        # negative delta is allowed for clock sync differences), and
        # must not fall outside the window
        if -5 <= delta <= window_seconds:
            candidates.append((delta, ev))

    if not candidates:
        return None

    # Return the closest (lowest-latency) match
    candidates.sort(key=lambda x: abs(x[0]))
    return candidates[0][1]


def run_validation(ground_truth_path: str, window_seconds: int = DEFAULT_MATCH_WINDOW_SECONDS) -> list:
    ground_truth = load_ground_truth(ground_truth_path)
    telemetry_events = load_telemetry_events(TELEMETRY_PATH)

    results = []
    for step in ground_truth:
        match = find_matching_detection(step, telemetry_events, window_seconds)

        if match:
            attack_time = parse_iso(step["timestamp"])
            detect_time = parse_iso(match["timestamp"])
            latency = (detect_time - attack_time).total_seconds()

            results.append(CoverageResult(
                attack_step=step["description"],
                vector=step["vector"],
                cve=step["cve"],
                mitre_technique=step.get("mitre_technique", ""),
                attack_timestamp=step["timestamp"],
                detected=True,
                detection_timestamp=match["timestamp"],
                detection_source=match["source"],
                detection_latency_seconds=round(latency, 2),
                matched_event_id=match["event_id"],
            ))
        else:
            results.append(CoverageResult(
                attack_step=step["description"],
                vector=step["vector"],
                cve=step["cve"],
                mitre_technique=step.get("mitre_technique", ""),
                attack_timestamp=step["timestamp"],
                detected=False,
            ))

    return results


def print_coverage_report(results: list):
    detected = [r for r in results if r.detected]
    missed = [r for r in results if not r.detected]

    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — PURPLE TEAM DETECTION COVERAGE REPORT")
    print("=" * 70)
    print(f"\nTotal attack steps:   {len(results)}")
    print(f"Detected:             {len(detected)}  ({len(detected)/len(results)*100:.0f}%)" if results else "Total: 0")
    print(f"Missed (FN):          {len(missed)}")

    if detected:
        avg_latency = sum(r.detection_latency_seconds for r in detected) / len(detected)
        print(f"Average detection latency (MTTD-like): {avg_latency:.1f}s")

    print("\n--- DETAIL ---")
    for r in results:
        status = f"DETECTED ({r.detection_source}, +{r.detection_latency_seconds}s)" if r.detected else "MISSED"
        print(f"[{r.vector}] {r.cve} — {r.attack_step}")
        print(f"    {status}")

    if missed:
        print("\nACTION FOR MISSED STEPS:")
        for r in missed:
            print(f"  - {r.attack_step} ({r.cve}): review the relevant Sigma rule in the WARDEN module,")
            print(f"    or confirm the telemetry source (auditd/eBPF/Apache log) covers this step.")


def export_results(results: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 validate.py <attack_log.json> [match_window_seconds]")
        print("Template: purple-team/attack_log_template.json")
        sys.exit(1)

    window = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_MATCH_WINDOW_SECONDS
    results = run_validation(sys.argv[1], window)
    print_coverage_report(results)

    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)
    export_results(results, os.path.join(output_dir, "coverage_results.json"))
