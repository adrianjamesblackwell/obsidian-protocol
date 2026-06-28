#!/usr/bin/env python3
"""
ioc-decay/ioc_decay.py

OBSIDIAN PROTOCOL — IOC Confidence & Decay Engine

REAL-WORLD PROBLEM: IP, domain, and hash IOCs "die" very fast — an IP
might belong to a malicious botnet today and be reassigned to a
completely legitimate cloud tenant three months later. Organizations
generally accumulate IOC lists but never clean them up, which leads
to a rising false-positive rate over time.

SOLUTION: this engine computes a CONFIDENCE score for each IOC — a
score that decays automatically over time, but rises again if the IOC
is re-observed (frequency) or corroborated by new sources
(source_count).

Formula:
    confidence = base_confidence * decay_factor(age) * frequency_boost * source_boost

  - decay_factor: exponential decay, half-life model (default 90 days)
  - frequency_boost: how many times it has been observed (log-scale)
  - source_boost: how many distinct independent sources corroborate it
"""

import json
import os
import math
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")

HALF_LIFE_DAYS = 90
BASE_CONFIDENCE = 100.0


@dataclass
class IOCRecord:
    ioc_value: str
    ioc_type: str
    first_seen: str
    last_seen: str
    frequency: int = 1
    source_count: int = 1
    sources: list = field(default_factory=list)


@dataclass
class IOCConfidenceResult:
    ioc_value: str
    ioc_type: str
    raw_confidence: float
    decayed_confidence: float
    age_days: float
    decay_factor: float
    frequency_boost: float
    source_boost: float
    confidence_band: str
    recommendation: str


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def decay_factor(age_days: float, half_life: float = HALF_LIFE_DAYS) -> float:
    return math.pow(0.5, age_days / half_life)


def frequency_boost(frequency: int) -> float:
    return 1.0 + math.log10(max(1, frequency)) * 0.3


def source_boost(source_count: int) -> float:
    return 1.0 + min(source_count - 1, 5) * 0.15


def confidence_band(score: float) -> tuple:
    if score >= 70:
        return ("ACTIVE", "High confidence - suitable for operational use")
    if score >= 40:
        return ("AGING", "Moderate confidence - re-verification recommended")
    if score >= 15:
        return ("STALE", "Low confidence - should not be used for active blocking, contextual reference only")
    return ("EXPIRED", "Below the confidence threshold - recommend removing from the blocklist")


def compute_confidence(ioc: IOCRecord, now: datetime = None) -> IOCConfidenceResult:
    now = now or datetime.now(timezone.utc)
    last_seen_dt = parse_iso(ioc.last_seen)
    age_days = (now - last_seen_dt).total_seconds() / 86400

    d_factor = decay_factor(age_days)
    f_boost = frequency_boost(ioc.frequency)
    s_boost = source_boost(ioc.source_count)

    raw = BASE_CONFIDENCE
    decayed = min(100.0, raw * d_factor * f_boost * s_boost)

    band, recommendation = confidence_band(decayed)

    return IOCConfidenceResult(
        ioc_value=ioc.ioc_value,
        ioc_type=ioc.ioc_type,
        raw_confidence=raw,
        decayed_confidence=round(decayed, 1),
        age_days=round(age_days, 1),
        decay_factor=round(d_factor, 3),
        frequency_boost=round(f_boost, 3),
        source_boost=round(s_boost, 3),
        confidence_band=band,
        recommendation=recommendation,
    )


def load_sample_iocs() -> list:
    iocs = [
        IOCRecord(
            ioc_value="GET /cgi-bin/%2e%2e/ (path traversal pattern)",
            ioc_type="http_pattern",
            first_seen="2026-06-27T10:15:00+00:00",
            last_seen="2026-06-27T10:15:32+00:00",
            frequency=12, source_count=2, sources=["Apache access log", "Sigma WARDEN"],
        ),
        IOCRecord(
            ioc_value="pkexec argc=0 + GCONV_PATH",
            ioc_type="process_pattern",
            first_seen="2026-06-27T10:18:00+00:00",
            last_seen="2026-06-27T10:18:05+00:00",
            frequency=3, source_count=2, sources=["auditd", "eBPF"],
        ),
        IOCRecord(
            ioc_value="185.220.101.45 (sample legacy C2 IP)",
            ioc_type="ip",
            first_seen="2025-12-01T00:00:00+00:00",
            last_seen="2025-12-10T00:00:00+00:00",
            frequency=45, source_count=3, sources=["AndroxGh0st campaign report (CISA AA24-016A context)"],
        ),
    ]
    return iocs


def print_report(results: list):
    print("=" * 70)
    print("  OBSIDIAN PROTOCOL — IOC CONFIDENCE & DECAY ENGINE")
    print(f"  (half-life: {HALF_LIFE_DAYS} days)")
    print("=" * 70)
    for r in results:
        print(f"\n[{r.confidence_band}] {r.ioc_value}")
        print(f"  Type: {r.ioc_type} | Age: {r.age_days} days")
        print(f"  Confidence: {r.decayed_confidence}/100  "
              f"(decay={r.decay_factor}, freq_boost={r.frequency_boost}, source_boost={r.source_boost})")
        print(f"  Recommendation: {r.recommendation}")


def main():
    iocs = load_sample_iocs()
    results = [compute_confidence(ioc) for ioc in iocs]
    print_report(results)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "ioc_confidence.json")
    with open(out_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved: {out_path}")


if __name__ == "__main__":
    main()
