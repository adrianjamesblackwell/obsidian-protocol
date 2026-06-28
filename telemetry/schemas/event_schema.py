"""
telemetry/schemas/event_schema.py

OBSIDIAN PROTOCOL — Common Telemetry Event Schema

This module converts data from EVERY source in the pipeline (auditd,
eBPF, Apache access log, Sigma matching engine) into ONE normalized
format. Why this matters: the Purple Team validation layer, the Risk
Engine, and the reporting engine all read this single format —
regardless of the original source.

This is a small-scale version of what real SIEM architectures
(Splunk CIM, Elastic ECS) do: "normalize data from different sources
into a common schema, so downstream analysis is source-agnostic."
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import json
import uuid


class EventSource(str, Enum):
    AUDITD = "auditd"
    APACHE_ACCESS_LOG = "apache_access_log"
    EBPF = "ebpf"
    SIGMA_MATCH = "sigma_match"
    MANUAL = "manual"  # event entered manually by the operator (e.g. a walkthrough step)


class EventCategory(str, Enum):
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    UNKNOWN = "unknown"


@dataclass
class ObsidianEvent:
    """
    A single normalized telemetry event.

    This is NOT a raw auditd line or a raw Apache access log line —
    it's the common format those get converted into by the parsers.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: EventSource = EventSource.MANUAL
    category: EventCategory = EventCategory.UNKNOWN

    # Attack chain context
    vector: Optional[str] = None          # "VECTOR-I" | "VECTOR-II" | None
    cve: Optional[str] = None              # "CVE-2021-41773" etc.
    mitre_technique: Optional[str] = None  # "T1190" etc.

    # Raw context
    host: Optional[str] = None             # "target-49"
    process: Optional[str] = None          # "pkexec", "httpd"
    user: Optional[str] = None             # "labuser", "root"
    raw_message: str = ""

    # Sigma/YARA match result, if any
    matched_rule_id: Optional[str] = None
    matched_rule_title: Optional[str] = None

    # Is this event a "ground truth" attack step (performed by the
    # operator), or a "detection" signal (caught by WARDEN)? The
    # Purple Team module matches these two against each other.
    is_offensive_action: bool = False
    is_detection_signal: bool = False

    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = self.source.value if isinstance(self.source, EventSource) else self.source
        d["category"] = self.category.value if isinstance(self.category, EventCategory) else self.category
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def load_events_ndjson(path: str) -> list:
    """Loads an event file in NDJSON (newline-delimited JSON) format."""
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def write_events_ndjson(events: list, path: str):
    """Writes a list of events to disk in NDJSON format (append-safe)."""
    with open(path, "a") as f:
        for ev in events:
            d = ev.to_dict() if isinstance(ev, ObsidianEvent) else ev
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
