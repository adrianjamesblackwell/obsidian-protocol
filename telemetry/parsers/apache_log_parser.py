"""
telemetry/parsers/apache_log_parser.py

OBSIDIAN PROTOCOL — Apache Access Log Parser

Parses Apache's standard "combined" log format and recognizes
VECTOR-I (CVE-2021-41773/42013) attack patterns (encoded path
traversal, CGI redirection).

Standard combined log format:
  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Example real line:
  172.18.0.3 - - [27/Jun/2026:10:15:32 +0000] "GET /cgi-bin/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 1024 "-" "curl/7.81.0"

This parser's recognition logic is the Python-side equivalent of the
Sigma rule in
detection/sigma/apache_path_traversal_cve_2021_41773.yml.
"""

import re
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "schemas"))
from event_schema import ObsidianEvent, EventSource, EventCategory


# Apache "combined" log format regex
COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)"'
)

# VECTOR-I recognition patterns (same logic as the Sigma rule)
TRAVERSAL_PATTERNS = ["%2e%2e/", "%2e%2e%2f", "..%2f", "..%c0%af", "%%32%65%%32%65"]
RCE_PATTERNS = ["/bin/sh", "/bin/bash"]
ANDROXGH0ST_PATTERNS = ["/.env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]


def parse_apache_timestamp(ts: str) -> str:
    """Converts an Apache log timestamp ([27/Jun/2026:10:15:32 +0000]) to ISO 8601."""
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def classify_apache_request(method: str, path: str) -> tuple:
    """
    Classifies whether an HTTP request matches the VECTOR-I (path
    traversal/RCE) pattern.
    """
    path_lower = path.lower()

    is_cgi_path = "/cgi-bin/" in path_lower
    has_traversal = any(p in path_lower for p in TRAVERSAL_PATTERNS)
    has_rce_target = any(p in path_lower for p in RCE_PATTERNS)
    has_androxgh0st = any(p in path_lower for p in ANDROXGH0ST_PATTERNS)

    if is_cgi_path and has_traversal and has_rce_target and method == "POST":
        return ("VECTOR-I", "CVE-2021-42013", "T1059", EventCategory.EXECUTION)
    if is_cgi_path and has_traversal:
        return ("VECTOR-I", "CVE-2021-41773", "T1190", EventCategory.INITIAL_ACCESS)
    if has_androxgh0st:
        # Not specific to this CVE, but an AndroxGh0st botnet IOC -
        # see docs/threat-intelligence.md
        return (None, None, "T1190", EventCategory.RECON)
    return (None, None, None, EventCategory.UNKNOWN)


def parse_apache_log(filepath: str) -> list:
    """Reads an Apache combined log file, converts it to a list of ObsidianEvent."""
    events = []
    with open(filepath) as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            match = COMBINED_LOG_PATTERN.match(raw_line)
            if not match:
                continue

            fields = match.groupdict()
            vector, cve, technique, category = classify_apache_request(
                fields["method"], fields["path"]
            )

            ev = ObsidianEvent(
                timestamp=parse_apache_timestamp(fields["time"]),
                source=EventSource.APACHE_ACCESS_LOG,
                category=category,
                vector=vector,
                cve=cve,
                mitre_technique=technique,
                host="target-49",
                process="httpd",
                user=None,
                raw_message=raw_line,
                is_detection_signal=(vector is not None),
                extra={
                    "src_ip": fields["ip"],
                    "method": fields["method"],
                    "path": fields["path"],
                    "status": fields["status"],
                    "user_agent": fields["useragent"],
                },
            )
            events.append(ev)
    return events


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apache_log_parser.py <access_log_file>")
        sys.exit(1)

    events = parse_apache_log(sys.argv[1])
    print(f"[*] {len(events)} HTTP request(s) parsed.")
    flagged = [e for e in events if e.vector or e.category != EventCategory.UNKNOWN]
    print(f"[*] {len(flagged)} request(s) matched a VECTOR-I/recon pattern:")
    for ev in flagged:
        print(f"  [{ev.vector or 'RECON'}] {ev.cve or '-'} - {ev.extra['method']} {ev.extra['path']} (src={ev.extra['src_ip']})")
