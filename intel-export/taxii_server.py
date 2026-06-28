#!/usr/bin/env python3
"""
intel-export/taxii_server.py

OBSIDIAN PROTOCOL — Minimal TAXII 2.1 Compliant Server

This is NOT a production-grade TAXII server (like OASIS's official
reference implementation or MITRE's Medallion). It's a minimal,
dependency-free (Python standard library only) reference server that
correctly implements the TAXII 2.1 specification's core endpoint
contract (discovery, api-root, collections, objects).

Purpose: to go beyond the claim "I can produce STIX/TAXII output" and
show how this data could ACTUALLY be consumed by a real TAXII client
(e.g. OpenCTI, MISP, or the stix2 library's TAXIICollection class).

Endpoints (TAXII 2.1 specification):
  GET /taxii2/                                    -> discovery
  GET /taxii2/api/                                  -> api-root info
  GET /taxii2/api/collections/                       -> collection list
  GET /taxii2/api/collections/{id}/objects/           -> STIX objects

Usage:
    python3 taxii_server.py
    # Then: curl http://localhost:8888/taxii2/
"""

import json
import os
import http.server
import socketserver

PORT = 8888
BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "output", "obsidian_protocol_bundle.stix2.json")
COLLECTION_ID = "obsidian-protocol-collection-001"

MEDIA_TYPE_TAXII = "application/taxii+json;version=2.1"
MEDIA_TYPE_STIX = "application/stix+json;version=2.1"


def load_bundle():
    if not os.path.exists(BUNDLE_PATH):
        return {"type": "bundle", "objects": []}
    with open(BUNDLE_PATH) as f:
        return json.load(f)


class ObsidianTAXIIHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, data: dict, media_type: str = MEDIA_TYPE_TAXII):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_404(self):
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"title": "Not Found", "http_status": "404"}).encode())

    def do_GET(self):
        path = self.path.rstrip("/")

        if path == "/taxii2" or path == "":
            self._send_json({
                "title": "OBSIDIAN PROTOCOL TAXII Server",
                "description": "Minimal TAXII 2.1 server for the VECTOR-I/VECTOR-II attack chain's IOC/CTI output.",
                "default": "/taxii2/api/",
                "api_roots": ["/taxii2/api/"],
            })

        elif path == "/taxii2/api":
            self._send_json({
                "title": "OBSIDIAN PROTOCOL API Root",
                "description": "STIX 2.1 objects produced by the WARDEN/SIGINT modules.",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 10485760,
            })

        elif path == "/taxii2/api/collections":
            self._send_json({
                "collections": [
                    {
                        "id": COLLECTION_ID,
                        "title": "OBSIDIAN PROTOCOL IOC Collection",
                        "description": "Indicator, vulnerability, attack-pattern, and malware objects "
                                        "for VECTOR-I (CVE-2021-41773/42013) and VECTOR-II (CVE-2021-4034).",
                        "can_read": True,
                        "can_write": False,
                        "media_types": [MEDIA_TYPE_STIX],
                    }
                ]
            })

        elif path == f"/taxii2/api/collections/{COLLECTION_ID}/objects":
            bundle = load_bundle()
            self._send_json({
                "objects": bundle.get("objects", []),
                "more": False,
            }, media_type=MEDIA_TYPE_STIX)

        else:
            self._send_404()

    def log_message(self, format, *args):
        print(f"[TAXII] {self.address_string()} - {format % args}")


def main():
    with socketserver.TCPServer(("0.0.0.0", PORT), ObsidianTAXIIHandler) as httpd:
        print(f"[+] OBSIDIAN PROTOCOL TAXII server running at http://localhost:{PORT}/taxii2/")
        print(f"[+] Discovery:    curl http://localhost:{PORT}/taxii2/")
        print(f"[+] Collections:  curl http://localhost:{PORT}/taxii2/api/collections/")
        print(f"[+] Objects:      curl http://localhost:{PORT}/taxii2/api/collections/{COLLECTION_ID}/objects/")
        print("[*] Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")


if __name__ == "__main__":
    main()
