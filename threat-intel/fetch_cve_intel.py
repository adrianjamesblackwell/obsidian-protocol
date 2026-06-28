#!/usr/bin/env python3
"""
threat-intel/fetch_cve_intel.py

This script pulls REAL data from public sources for the CVEs used in
this lab:

  1. NVD API (National Vulnerability Database, NIST)
     -> CVSS score, CWE category, affected product/version list
  2. CISA KEV (Known Exploited Vulnerabilities Catalog)
     -> Official evidence that this CVE has ACTUALLY been exploited,
        the date it was added to KEV, the remediation deadline for
        federal agencies (this gives an official answer to "how
        urgent/active is this")
  3. KNOWN_CAMPAIGNS (manually compiled, sourced from CISA/FBI/Imperva)
     -> Known botnet/malware campaigns using this CVE, sectors
        targeted in 2024. This data doesn't come from a live API
        because no such public API exists; it was manually compiled
        instead from the official advisories referenced in
        docs/threat-intelligence.md (CISA AA24-016A, etc.).

All sources are free and require no API key (NVD recommends an
optional key for rate limiting; this script is written to work
without one).

Usage:
    python3 fetch_cve_intel.py CVE-2021-41773 CVE-2021-42013 CVE-2021-4034
"""

import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Known campaign/botnet mapping -- this is NOT available in the
# NVD/KEV APIs; it was manually compiled from public CISA/FBI
# advisories (AA24-016A) and Imperva Threat Research publications.
# Source: docs/threat-intelligence.md
KNOWN_CAMPAIGNS = {
    "CVE-2021-41773": {
        "known_botnets": ["AndroxGh0st"],
        "known_malware_payloads": ["Linuxsys cryptominer", "XMRig"],
        "targeted_sectors_2024": ["Financial Services", "Business"],
        "attributed_actors": "CISA: listed among CVEs frequently used by China-affiliated threat actors",
        "source": "CISA AA24-016A, Imperva Threat Research 2024",
    },
    "CVE-2021-42013": {
        "known_botnets": ["AndroxGh0st"],
        "known_malware_payloads": ["Linuxsys cryptominer", "XMRig"],
        "targeted_sectors_2024": ["Financial Services", "Business"],
        "attributed_actors": "CISA: listed among CVEs frequently used by China-affiliated threat actors",
        "source": "CISA AA24-016A, Imperva Threat Research 2024",
    },
    "CVE-2021-4034": {
        "known_botnets": [],
        "known_malware_payloads": [],
        "targeted_sectors_2024": ["Local privilege escalation - generally the 2nd step of a chain, limited standalone campaign data"],
        "attributed_actors": "General purpose - usable after any local foothold",
        "source": "Qualys Security Advisory 2022-01-25",
    },
}


def fetch_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "obsidian-protocol-sigint/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  [!] HTTP error ({url}): {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [!] Request error ({url}): {e}", file=sys.stderr)
        return None


def get_nvd_data(cve_id):
    """Fetches CVSS score, description, and CWE info from NVD."""
    url = f"{NVD_API}?cveId={cve_id}"
    data = fetch_json(url)
    if not data or not data.get("vulnerabilities"):
        return None

    cve = data["vulnerabilities"][0]["cve"]
    result = {"cve_id": cve_id, "description": None, "cvss_v3": None, "cwe": [], "published": cve.get("published")}

    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            result["description"] = desc.get("value")
            break

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key][0]["cvssData"]
            result["cvss_v3"] = {
                "score": m.get("baseScore"),
                "severity": metrics[key][0].get("baseSeverity", "N/A"),
                "vector": m.get("vectorString"),
            }
            break

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("lang") == "en":
                result["cwe"].append(desc.get("value"))

    return result


def get_kev_status(cve_id, kev_catalog):
    """Is this CVE on CISA's 'actually exploited' list?"""
    if not kev_catalog:
        return {"in_kev": False, "note": "Could not fetch KEV data"}

    for vuln in kev_catalog.get("vulnerabilities", []):
        if vuln.get("cveID") == cve_id:
            return {
                "in_kev": True,
                "date_added": vuln.get("dateAdded"),
                "vendor_project": vuln.get("vendorProject"),
                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": vuln.get("requiredAction"),
                "due_date": vuln.get("dueDate"),
            }
    return {"in_kev": False, "note": "This CVE is not on the CISA KEV list (no official 'active exploitation' evidence)"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fetch_cve_intel.py CVE-XXXX-XXXX [CVE-YYYY-YYYY ...]")
        sys.exit(1)

    cve_ids = sys.argv[1:]
    print(f"[*] Downloading the CISA KEV catalog (once, for all CVEs)...")
    kev_catalog = fetch_json(KEV_FEED)
    if kev_catalog:
        print(f"[+] KEV catalog contains {len(kev_catalog.get('vulnerabilities', []))} entries.\n")

    results = {}
    for cve_id in cve_ids:
        print(f"[*] Fetching NVD data for {cve_id}...")
        nvd_data = get_nvd_data(cve_id)
        time.sleep(6)  # respect NVD's public rate limit (~5 req/30s without a key)

        kev_data = get_kev_status(cve_id, kev_catalog)
        campaign_data = KNOWN_CAMPAIGNS.get(cve_id, {"note": "No known campaign data has been compiled"})

        results[cve_id] = {"nvd": nvd_data, "kev": kev_data, "known_campaigns": campaign_data}

        if nvd_data:
            print(f"    CVSS: {nvd_data['cvss_v3']}")
        print(f"    KEV status: {'YES - actively exploited' if kev_data['in_kev'] else 'No'}")
        if kev_data.get("in_kev"):
            print(f"    Added to KEV on: {kev_data['date_added']}")
            print(f"    Known ransomware use: {kev_data['known_ransomware_use']}")
        if campaign_data.get("known_botnets"):
            print(f"    Known botnet(s): {', '.join(campaign_data['known_botnets'])}")
        if campaign_data.get("targeted_sectors_2024"):
            print(f"    Sectors targeted in 2024: {', '.join(campaign_data['targeted_sectors_2024'])}")
        print()

    out_path = "threat-intel/cve_intel_output.json"
    with open(out_path, "w") as f:
        json.dump({"generated_at": datetime.utcnow().isoformat(), "results": results}, f, indent=2)

    print(f"[+] Results saved: {out_path}")


if __name__ == "__main__":
    main()
