#!/usr/bin/env python3
"""
correlation-engine/correlate.py

OBSIDIAN PROTOCOL — Event Correlation Engine (Alert Fatigue Solution)

REAL-WORLD PROBLEM: SOC teams see 20,000-200,000+ alerts a day. Most
of those aren't "false alarms" — the real problem is that alerts can't
be tied to each other. Apache exploit + sudo + curl + bash + systemd
looks like 5 separate alerts, but is actually the steps of ONE attack
operation.

SOLUTION: groups the raw events in
telemetry/output/unified_timeline.ndjson along three dimensions:
  1. Actor identity   -> src_ip (network events) or user (host events)
  2. Time window        -> default 300s, are these part of the same operation
  3. Causal chain         -> does the observed MITRE technique sequence
                             fit a known kill-chain pattern (KNOWN_CHAIN_PATTERNS)

Output: M "Correlated Incidents" instead of N raw events (M << N),
each with its own confidence score.

Usage:
    python3 correlation-engine/correlate.py [window_seconds]
"""

import json
import os
import sys
import hashlib
from datetime import datetime
from dataclasses import dataclass, asdict, field

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
TELEMETRY_PATH = os.path.join(BASE_DIR, "telemetry", "output", "unified_timeline.ndjson")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
DEFAULT_WINDOW_SECONDS = 300

# Known kill-chain patterns: MITRE technique ordering.
# This encodes this project's own VECTOR-I/II chain (see the "Known
# Limitation" note in the README — in production this list could be
# derived from MITRE's official campaign/group dataset instead).
KNOWN_CHAIN_PATTERNS = [
    {
        "name": "VECTOR-I: Web RCE Kill-Chain",
        "sequence": ["T1190", "T1059"],
        "severity": "HIGH",
    },
    {
        "name": "VECTOR-I -> VECTOR-II: Full Chain (RCE -> PrivEsc)",
        "sequence": ["T1190", "T1059", "T1548.001"],
        "severity": "CRITICAL",
    },
    {
        "name": "VECTOR-II: Local Privilege Escalation",
        "sequence": ["T1548.001"],
        "severity": "HIGH",
    },
]


@dataclass
class CorrelatedIncident:
    incident_id: str
    first_seen: str
    last_seen: str
    actor_key: str
    raw_event_count: int
    mitre_chain: list
    cve_chain: list
    vectors: list
    confidence: float
    confidence_rationale: str
    severity: str
    raw_event_ids: list = field(default_factory=list)
    narrative: str = ""


def load_telemetry_events(path: str) -> list:
    if not os.path.exists(path):
        print(f"[!] Telemetry file not found: {path}")
        print("[!] Run first: python3 telemetry/build_timeline.py --live")
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


def get_actor_key(event: dict) -> str:
    """
    Extracts the actor identity: src_ip for network-based events, user
    for host-based events. This is an approximate answer to "did the
    same attacker/session produce these events."
    """
    extra = event.get("extra", {})
    if "src_ip" in extra:
        return f"ip:{extra['src_ip']}"
    if event.get("user"):
        return f"user:{event['user']}"
    return f"host:{event.get('host', 'unknown')}"


def match_chain_pattern(mitre_sequence: list) -> tuple:
    """
    Checks whether the observed MITRE technique sequence matches a
    known kill-chain pattern. Distinguishes exact match, subset match,
    and "no match" cases.

    Returns: (matched_pattern_name_or_None, confidence_score, rationale, severity)
    """
    if len(mitre_sequence) == 0:
        return (None, 0.0, "No events", "LOW")

    if len(mitre_sequence) == 1:
        return (None, 20.0, "A single technique observed, no chain could be formed", "LOW")

    for pattern in KNOWN_CHAIN_PATTERNS:
        if mitre_sequence == pattern["sequence"]:
            return (
                pattern["name"], 95.0,
                f"Exact match: known kill-chain pattern {' -> '.join(mitre_sequence)}",
                pattern["severity"],
            )

    # Subset match: does the observed sequence fit the beginning
    # (prefix) of a known pattern? (e.g. the attack may not be complete yet)
    for pattern in KNOWN_CHAIN_PATTERNS:
        seq_len = len(mitre_sequence)
        if pattern["sequence"][:seq_len] == mitre_sequence and seq_len < len(pattern["sequence"]):
            return (
                pattern["name"], 70.0,
                f"Partial match: observed techniques are a subset of pattern '{pattern['name']}' "
                f"(the attack may not be complete yet)",
                "MEDIUM",
            )

    return (
        None, 40.0,
        f"Multiple techniques present ({', '.join(mitre_sequence)}) but doesn't fit any recognized chain",
        "MEDIUM",
    )


def build_narrative(events: list) -> str:
    """Builds a human-readable summary sentence from a list of events."""
    parts = []
    for ev in events:
        cat = ev.get("category", "unknown")
        cve = ev.get("cve")
        source = ev.get("source", "unknown source")
        label = f"'{cat}' from {source}" + (f" ({cve})" if cve else "")
        parts.append(label)
    return " followed by ".join(parts)


def correlate_events(events: list, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list:
    """
    Main correlation algorithm:
      1. Group events by actor identity
      2. Sort each actor group internally by time
      3. Group events falling within the same time window
         (window_seconds) under a single "incident"
      4. Extract each incident's MITRE technique sequence, match it
         against known kill-chain patterns, and assign a confidence score
    """
    relevant_events = [e for e in events if e.get("mitre_technique") or e.get("vector")]

    by_actor = {}
    for ev in relevant_events:
        key = get_actor_key(ev)
        by_actor.setdefault(key, []).append(ev)

    incidents = []
    for actor_key, actor_events in by_actor.items():
        actor_events.sort(key=lambda e: e["timestamp"])

        current_group = []
        for ev in actor_events:
            if not current_group:
                current_group.append(ev)
                continue

            last_ts = parse_iso(current_group[-1]["timestamp"])
            curr_ts = parse_iso(ev["timestamp"])
            delta = (curr_ts - last_ts).total_seconds()

            if 0 <= delta <= window_seconds:
                current_group.append(ev)
            else:
                incidents.append(_build_incident(actor_key, current_group))
                current_group = [ev]

        if current_group:
            incidents.append(_build_incident(actor_key, current_group))

    return incidents


def _build_incident(actor_key: str, events: list) -> CorrelatedIncident:
    mitre_sequence = [e["mitre_technique"] for e in events if e.get("mitre_technique")]
    cve_chain = sorted(set(e["cve"] for e in events if e.get("cve")))
    vectors = sorted(set(e["vector"] for e in events if e.get("vector")))

    pattern_name, confidence, rationale, severity = match_chain_pattern(mitre_sequence)

    incident_hash = hashlib.sha256(
        f"{actor_key}-{events[0]['timestamp']}-{events[-1]['timestamp']}".encode()
    ).hexdigest()[:8]

    return CorrelatedIncident(
        incident_id=incident_hash,
        first_seen=events[0]["timestamp"],
        last_seen=events[-1]["timestamp"],
        actor_key=actor_key,
        raw_event_count=len(events),
        mitre_chain=mitre_sequence,
        cve_chain=cve_chain,
        vectors=vectors,
        confidence=confidence,
        confidence_rationale=rationale,
        severity=severity,
        raw_event_ids=[e["event_id"] for e in events],
        narrative=build_narrative(events),
    )


def print_report(incidents: list, raw_event_count: int):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — EVENT CORRELATION ENGINE")
    print("=" * 70)
    print(f"\n  Raw event count:        {raw_event_count}")
    print(f"  Correlated Incidents:   {len(incidents)}")
    if raw_event_count > 0:
        reduction = (1 - len(incidents) / raw_event_count) * 100
        print(f"  Alert reduction ratio:  {reduction:.0f}%  (N raw events -> M incidents)")

    print("\n  --- INCIDENT DETAIL ---\n")
    for inc in sorted(incidents, key=lambda i: -i.confidence):
        print(f"  [{inc.severity:8s}] {inc.incident_id}  (confidence: {inc.confidence:.0f}%)")
        print(f"    Actor: {inc.actor_key}")
        print(f"    Chain: {' -> '.join(inc.mitre_chain) if inc.mitre_chain else '-'}")
        print(f"    CVE: {', '.join(inc.cve_chain) if inc.cve_chain else '-'}")
        print(f"    Rationale: {inc.confidence_rationale}")
        print(f"    Narrative: {inc.narrative}")
        print()


def main():
    window = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WINDOW_SECONDS

    events = load_telemetry_events(TELEMETRY_PATH)
    if not events:
        sys.exit(1)

    incidents = correlate_events(events, window)
    print_report(incidents, len(events))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "correlated_incidents.json")
    with open(output_path, "w") as f:
        json.dump([asdict(i) for i in incidents], f, indent=2, ensure_ascii=False)
    print(f"[+] Results saved: {output_path}")


if __name__ == "__main__":
    main()
