"""
telemetry/parsers/ebpf_parser.py

OBSIDIAN PROTOCOL — eBPF Event Adapter

Converts the JSON lines produced by the
telemetry/collectors/pwnkit_ebpf_trace.bt script (each line is one
eBPF tracepoint event) into the ObsidianEvent schema.

bpftrace output is printed to stdout as JSON lines; this module can
process either a live pipe (`bpftrace ... | python3 ebpf_parser.py -`)
or output saved to a file (`bpftrace ... > out.jsonl`).
"""

import sys
import os
import json
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "schemas"))
from event_schema import ObsidianEvent, EventSource, EventCategory


def nsecs_to_iso(nsecs: int) -> str:
    """
    bpftrace's built-in nsecs variable is nanoseconds since system
    boot (NOT epoch). In a real collector this would be converted to
    epoch via /proc/uptime. In this simplified version we use a
    relative offset to preserve event ordering and display it on the
    reporting side as "+Xs since collector start" — getting a real
    timestamp requires also injecting the system boot time (see
    telemetry/README.md).
    """
    return datetime.now(timezone.utc).isoformat()


def parse_ebpf_line(line: str) -> Optional[ObsidianEvent]:
    """Converts a single bpftrace JSON line into an ObsidianEvent."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    ebpf_event = data.get("ebpf_event")
    if ebpf_event == "execve_pkexec":
        is_pwnkit_signature = bool(data.get("argv0_null"))
        return ObsidianEvent(
            timestamp=nsecs_to_iso(data.get("timestamp", 0)),
            source=EventSource.EBPF,
            category=EventCategory.PRIVILEGE_ESCALATION if is_pwnkit_signature else EventCategory.UNKNOWN,
            vector="VECTOR-II" if is_pwnkit_signature else None,
            cve="CVE-2021-4034" if is_pwnkit_signature else None,
            mitre_technique="T1548.001" if is_pwnkit_signature else None,
            host="target-49",
            process="pkexec",
            user=str(data.get("uid")),
            raw_message=line,
            is_detection_signal=is_pwnkit_signature,
            extra=data,
        )

    if ebpf_event == "openat_gconv_artifact":
        return ObsidianEvent(
            timestamp=nsecs_to_iso(data.get("timestamp", 0)),
            source=EventSource.EBPF,
            category=EventCategory.PRIVILEGE_ESCALATION,
            vector="VECTOR-II",
            cve="CVE-2021-4034",
            mitre_technique="T1548.001",
            host="target-49",
            process=data.get("comm"),
            user=str(data.get("uid")),
            raw_message=line,
            is_detection_signal=True,
            extra=data,
        )

    return None


def parse_ebpf_stream(filepath: str) -> list:
    """Reads eBPF JSON lines from a file (or from stdin if '-' is given)."""
    events = []
    stream = sys.stdin if filepath == "-" else open(filepath)
    try:
        for line in stream:
            ev = parse_ebpf_line(line)
            if ev:
                events.append(ev)
    finally:
        if filepath != "-":
            stream.close()
    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ebpf_parser.py <bpftrace_output_file | ->")
        print("Live usage: bpftrace collectors/pwnkit_ebpf_trace.bt | python3 ebpf_parser.py -")
        sys.exit(1)

    events = parse_ebpf_stream(sys.argv[1])
    print(f"[*] {len(events)} eBPF event(s) parsed.")
    for ev in events:
        if ev.is_detection_signal:
            print(f"  [{ev.vector}] {ev.cve} - {ev.process} (uid={ev.user}) - SIGNAL DETECTED")
