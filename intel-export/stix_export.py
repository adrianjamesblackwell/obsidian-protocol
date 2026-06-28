#!/usr/bin/env python3
"""
intel-export/stix_export.py

OBSIDIAN PROTOCOL — STIX 2.1 / IOC Export

This module exports the IOCs produced by the operation (path
traversal patterns, PwnKit artifact signatures, MITRE technique
mappings) as a JSON bundle compliant with the REAL STIX 2.1
specification.

Note: raw JSON generation is used instead of the stix2 Python library
— this gives spec-compliant output without an extra dependency (also
works in environments where the library can't be installed). Format
reference: the OASIS STIX 2.1 specification (indicator, malware,
relationship, attack-pattern SDOs/SROs).

STIX object types produced:
  - indicator       : path traversal/RCE/PwnKit detection patterns
  - malware         : AndroxGh0st (a real, named botnet)
  - attack-pattern  : the MITRE ATT&CK equivalent of VECTOR-I and VECTOR-II
  - vulnerability   : a separate object per CVE
  - relationship    : SROs connecting all of the above

Output: intel-export/output/obsidian_protocol_bundle.stix2.json
"""

import json
import os
import uuid
from datetime import datetime, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "obsidian_protocol_bundle.stix2.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


def make_vulnerability(cve: str, description: str) -> dict:
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id("vulnerability"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": cve,
        "description": description,
        "external_references": [
            {"source_name": "cve", "external_id": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
        ],
    }


def make_attack_pattern(name: str, mitre_id: str, description: str) -> dict:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": stix_id("attack-pattern"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "description": description,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": mitre_id,
                "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            }
        ],
    }


def make_indicator(name: str, pattern: str, description: str, valid_from: str = None) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id("indicator"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "pattern": pattern,
        "valid_from": valid_from or now_iso(),
    }


def make_malware(name: str, description: str, is_family: bool = True) -> dict:
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id("malware"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "description": description,
        "is_family": is_family,
        "malware_types": ["bot"],
    }


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, description: str = "") -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship"),
        "created": now_iso(),
        "modified": now_iso(),
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description,
    }


def build_bundle() -> dict:
    objects = []

    # --- Vulnerability objects ---
    vuln_41773 = make_vulnerability(
        "CVE-2021-41773",
        "Apache HTTP Server 2.4.49 path traversal vulnerability. "
        "Completed by CVE-2021-42013 due to an incomplete patch."
    )
    vuln_42013 = make_vulnerability(
        "CVE-2021-42013",
        "Apache HTTP Server 2.4.49/2.4.50 path traversal and RCE. "
        "The completed form of CVE-2021-41773's incomplete patch."
    )
    vuln_4034 = make_vulnerability(
        "CVE-2021-4034",
        "polkit pkexec local privilege escalation (PwnKit). "
        "An argc=0 logic flaw, exploited via GCONV_PATH environment variable manipulation."
    )
    objects.extend([vuln_41773, vuln_42013, vuln_4034])

    # --- Attack Pattern (MITRE ATT&CK) objects ---
    ap_initial_access = make_attack_pattern(
        "Exploit Public-Facing Application (VECTOR-I)", "T1190",
        "Initial access via Apache path traversal."
    )
    ap_execution = make_attack_pattern(
        "Command and Scripting Interpreter (VECTOR-I RCE)", "T1059",
        "Command execution via CGI redirection."
    )
    ap_privesc = make_attack_pattern(
        "Abuse Elevation Control Mechanism: Setuid/Setgid (VECTOR-II)", "T1548.001",
        "Escalation to root via PwnKit's pkexec/SUID exploitation."
    )
    objects.extend([ap_initial_access, ap_execution, ap_privesc])

    # --- Indicator objects (real detection patterns - from the WARDEN module) ---
    ind_traversal = make_indicator(
        "Apache Path Traversal - Encoded Double-Dot Sequence",
        "[network-traffic:extensions.http-request-ext.request_value MATCHES '.*%2e%2e/.*cgi-bin.*']",
        "An encoded path traversal pattern used via the /cgi-bin/ ScriptAlias path. "
        "WARDEN/Sigma rule: detection/sigma/apache_path_traversal_cve_2021_41773.yml"
    )
    ind_pwnkit = make_indicator(
        "PwnKit pkexec argc=0 Exploitation",
        "[process:name = 'pkexec' AND process:command_line = '' AND process:environment_variables.GCONV_PATH MATCHES '.*']",
        "pkexec invoked with no arguments (argc=0) combined with GCONV_PATH environment "
        "variable manipulation. WARDEN/Sigma rule: detection/sigma/pwnkit_cve_2021_4034.yml"
    )
    ind_androxgh0st = make_indicator(
        "AndroxGh0st Botnet - .env Scanning Pattern",
        "[url:value MATCHES '.*\\\\.env$' OR url:value MATCHES '.*eval-stdin\\\\.php$']",
        "The AndroxGh0st botnet IOC pattern described in the FBI/CISA AA24-016A advisory "
        "(.env file scanning, PHPUnit eval-stdin.php exploitation attempt)."
    )
    objects.extend([ind_traversal, ind_pwnkit, ind_androxgh0st])

    # --- Malware object (a real, named botnet) ---
    malware_androxgh0st = make_malware(
        "AndroxGh0st",
        "A Python-based botnet, first identified by Lacework in December 2022. "
        "Scans Laravel .env files attempting to steal AWS/Microsoft 365/SendGrid/Twilio "
        "credentials. Uses CVE-2021-41773, CVE-2017-9841, and CVE-2018-15133. "
        "Source: CISA/FBI AA24-016A.",
    )
    objects.append(malware_androxgh0st)

    # --- Relationships (SROs) ---
    objects.append(make_relationship(ind_traversal["id"], vuln_41773["id"], "indicates", "Indicator of CVE-2021-41773 exploitation"))
    objects.append(make_relationship(ind_traversal["id"], vuln_42013["id"], "indicates", "Indicator of CVE-2021-42013 exploitation"))
    objects.append(make_relationship(ind_pwnkit["id"], vuln_4034["id"], "indicates", "Indicator of CVE-2021-4034 exploitation"))
    objects.append(make_relationship(vuln_41773["id"], ap_initial_access["id"], "exploits", "VECTOR-I initial access"))
    objects.append(make_relationship(vuln_42013["id"], ap_execution["id"], "exploits", "VECTOR-I execution/RCE"))
    objects.append(make_relationship(vuln_4034["id"], ap_privesc["id"], "exploits", "VECTOR-II privilege escalation"))
    objects.append(make_relationship(malware_androxgh0st["id"], vuln_41773["id"], "uses", "AndroxGh0st uses CVE-2021-41773 (CISA AA24-016A)"))
    objects.append(make_relationship(ind_androxgh0st["id"], malware_androxgh0st["id"], "indicates", "Indicator of AndroxGh0st activity"))

    bundle = {
        "type": "bundle",
        "id": stix_id("bundle"),
        "objects": objects,
    }
    return bundle


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    bundle = build_bundle()

    with open(OUTPUT_PATH, "w") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    print(f"[+] STIX 2.1 bundle generated: {OUTPUT_PATH}")
    print(f"[+] Total {len(bundle['objects'])} STIX object(s).")
    type_counts = {}
    for obj in bundle["objects"]:
        type_counts[obj["type"]] = type_counts.get(obj["type"], 0) + 1
    for t, c in type_counts.items():
        print(f"    {t}: {c}")


if __name__ == "__main__":
    main()
