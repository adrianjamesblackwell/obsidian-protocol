"""
telemetry/parsers/auditd_parser.py

OBSIDIAN PROTOCOL — auditd Log Parser

This parser processes REAL auditd lines from `ausearch -k pkexec_exec
--format raw` or `/var/log/audit/audit.log` output and converts them
into the ObsidianEvent schema.

Real auditd format example (the line format seen when the PwnKit
exploit fires, reference: Sysdig/Wazuh detection blog posts):

    type=EXECVE msg=audit(1706000000.123:456): argc=0 a0="/usr/bin/pkexec"
    type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59
    ...uid=1000 ... comm="pkexec" exe="/usr/bin/pkexec" ...

This module parses auditd's "type=" key-value format.
"""

import re
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "schemas"))
from event_schema import ObsidianEvent, EventSource, EventCategory


# auditd lines are in "key=value key="quoted value" ..." format
KV_PATTERN = re.compile(r'(\w+)=(".*?"|\S+)')


def parse_auditd_line(line: str) -> dict:
    """Converts a single auditd line into a key-value dict."""
    fields = {}
    for match in KV_PATTERN.finditer(line):
        key, value = match.group(1), match.group(2)
        fields[key] = value.strip('"')
    return fields


def auditd_timestamp_to_iso(msg_field: str) -> str:
    """
    Converts auditd's epoch timestamp in msg=audit(1706000000.123:456)
    format to ISO 8601.
    """
    match = re.search(r'audit\((\d+)\.(\d+):', msg_field)
    if not match:
        return datetime.now(timezone.utc).isoformat()
    epoch_seconds = int(match.group(1))
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def classify_auditd_event(fields: dict) -> tuple:
    """
    Classifies which VECTOR and MITRE technique this event corresponds
    to, based on the parsed auditd fields.

    This is the Python-side equivalent of the logic in the WARDEN
    module's Sigma rule (pwnkit_cve_2021_4034.yml): the pkexec +
    argc=0 + GCONV_PATH pattern means a VECTOR-II / PwnKit signal.
    """
    exe = fields.get("exe", fields.get("comm", ""))
    argc = fields.get("argc", "")
    env_hint = fields.get("a1", "") + fields.get("a2", "")

    if "pkexec" in exe and argc == "0":
        return ("VECTOR-II", "CVE-2021-4034", "T1548.001", EventCategory.PRIVILEGE_ESCALATION)
    if "pkexec" in exe and "GCONV_PATH" in env_hint:
        return ("VECTOR-II", "CVE-2021-4034", "T1548.001", EventCategory.PRIVILEGE_ESCALATION)
    return (None, None, None, EventCategory.UNKNOWN)


def extract_audit_event_id(line: str) -> str:
    """
    auditd splits a single logical event (e.g. one execve call) across
    multiple lines (SYSCALL, EXECVE, CWD, PATH...). The shared key to
    join them back together is the ID portion inside
    msg=audit(seconds.milliseconds:ID).
    """
    match = re.search(r'audit\(([\d.]+:\d+)\)', line)
    return match.group(1) if match else line[:40]


def parse_auditd_log(filepath: str) -> list:
    """
    Reads an auditd log file (ausearch output or audit.log).

    CRITICAL BEHAVIOR: auditd splits a single logical event (e.g.
    pkexec's execve call) across multiple lines like SYSCALL + EXECVE
    + CWD + PATH — these share the same audit(seconds:ID) key. For
    correct classification we need to group these lines first, THEN
    look at the combined field set. Classifying on a single line alone
    (e.g. only looking at the EXECVE line) often misses fields like
    "comm"/"exe", since those live on the SYSCALL line.
    """
    grouped_fields = {}   # audit_event_id -> combined fields dict
    line_order = []       # preserves first-seen order
    raw_lines_by_id = {}

    with open(filepath) as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line or "type=" not in raw_line:
                continue

            event_id = extract_audit_event_id(raw_line)
            fields = parse_auditd_line(raw_line)

            if event_id not in grouped_fields:
                grouped_fields[event_id] = {}
                line_order.append(event_id)
                raw_lines_by_id[event_id] = []

            grouped_fields[event_id].update(fields)
            raw_lines_by_id[event_id].append(raw_line)

    events = []
    for event_id in line_order:
        fields = grouped_fields[event_id]
        vector, cve, technique, category = classify_auditd_event(fields)
        ts = auditd_timestamp_to_iso(fields.get("msg", ""))
        combined_raw = " | ".join(raw_lines_by_id[event_id])

        ev = ObsidianEvent(
            timestamp=ts,
            source=EventSource.AUDITD,
            category=category,
            vector=vector,
            cve=cve,
            mitre_technique=technique,
            host=fields.get("hostname", "target-49"),
            process=fields.get("comm") or fields.get("exe"),
            user=fields.get("uid"),
            raw_message=combined_raw,
            is_detection_signal=(vector is not None),
            extra=fields,
        )
        events.append(ev)
    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 auditd_parser.py <audit_log_file>")
        print("Example generation: ausearch -k pkexec_exec --format raw > sample.log")
        sys.exit(1)

    events = parse_auditd_log(sys.argv[1])
    print(f"[*] {len(events)} event(s) parsed.")
    for ev in events:
        if ev.vector:
            print(f"  [{ev.vector}] {ev.cve} - {ev.process} (user={ev.user}) @ {ev.timestamp}")
