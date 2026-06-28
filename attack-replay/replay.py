#!/usr/bin/env python3
"""
attack-replay/replay.py

OBSIDIAN PROTOCOL — Attack Replay Engine

REAL-WORLD PROBLEM: A post-incident review is usually presented as a
static report — the reader never feels the real-time flow of the
event. Saying "recon started at 08:20, detected at 08:28" is a very
different sense-making experience from showing it step by step, as a
replay played out against real timestamps.

SOLUTION: this engine combines telemetry + Purple Team data to present
the operation as a CHRONOLOGICAL replay. Two modes: instant (print
everything immediately) and --live (simulating real time intervals).
"""

import json
import os
import sys
import time
from datetime import datetime

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_timeline_events() -> list:
    path = os.path.join(BASE_DIR, "telemetry", "output", "unified_timeline.ndjson")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        events = [json.loads(line) for line in f if line.strip()]
    events.sort(key=lambda e: e["timestamp"])
    return events


def load_coverage_results() -> dict:
    path = os.path.join(BASE_DIR, "purple-team", "output", "coverage_results.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        results = json.load(f)
    return {r["matched_event_id"]: r for r in results if r.get("matched_event_id")}


def build_replay_steps(events: list, coverage_by_event: dict) -> list:
    steps = []
    for ev in events:
        coverage_info = coverage_by_event.get(ev["event_id"])
        steps.append({
            "timestamp": ev["timestamp"],
            "source": ev["source"],
            "vector": ev.get("vector"),
            "cve": ev.get("cve"),
            "category": ev.get("category"),
            "mitre_technique": ev.get("mitre_technique"),
            "is_offensive_action": ev.get("is_offensive_action"),
            "is_detection_signal": ev.get("is_detection_signal"),
            "detected_by_purple_team": coverage_info is not None and coverage_info.get("detected"),
            "raw_message_preview": ev.get("raw_message", "")[:80],
        })
    return steps


def format_time_short(ts: str) -> str:
    dt = parse_iso(ts)
    return dt.strftime("%H:%M:%S")


def print_replay(steps: list, live: bool = False, speed: float = 1.0):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — ATTACK REPLAY")
    print("=" * 70)
    print()

    prev_time = None
    for step in steps:
        this_time = parse_iso(step["timestamp"])
        delta_str = ""
        if prev_time:
            delta_s = (this_time - prev_time).total_seconds()
            delta_str = f"  (+{delta_s:.0f}s)"
            if live:
                time.sleep(min(abs(delta_s) / max(speed, 0.01), 5))
        prev_time = this_time

        if step["is_offensive_action"]:
            marker = "[OFFENSIVE]"
        elif step["detected_by_purple_team"]:
            marker = "[DETECTED] "
        elif step["is_detection_signal"]:
            marker = "[SIGNAL]   "
        else:
            marker = "[INFO]     "

        vector_part = f"[{step['vector']}] " if step["vector"] else ""
        cve_part = f"{step['cve']} " if step["cve"] else ""

        print(f"  {format_time_short(step['timestamp'])}{delta_str}")
        print(f"    {marker}  {vector_part}{cve_part}{step['category'] or ''}")
        print(f"    source: {step['source']} | {step['raw_message_preview']}")
        print()

    print("=" * 70)
    print(f"  REPLAY COMPLETE — {len(steps)} step(s)")
    detected_count = sum(1 for s in steps if s["detected_by_purple_team"])
    offensive_count = sum(1 for s in steps if s["is_offensive_action"])
    print(f"  Offensive action(s): {offensive_count} | Detections confirmed by Purple Team: {detected_count}")


def main():
    live = "--live" in sys.argv
    speed = 1.0
    for arg in sys.argv:
        if arg.startswith("--speed="):
            speed = float(arg.split("=")[1])

    events = load_timeline_events()
    if not events:
        print("[!] No telemetry data found.")
        print("[!] Run first: python3 telemetry/build_timeline.py --live")
        return

    coverage_by_event = load_coverage_results()
    steps = build_replay_steps(events, coverage_by_event)

    print_replay(steps, live=live, speed=speed)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "replay_timeline.json")
    with open(out_path, "w") as f:
        json.dump(steps, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Replay data saved: {out_path}")
    print("[+] For live playback: python3 attack-replay/replay.py --live --speed=10")


if __name__ == "__main__":
    main()
