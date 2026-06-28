# INTEL EXPORT
### OBSIDIAN PROTOCOL / STIX 2.1 + TAXII 2.1 Output

This module exports the IOCs and CTI context produced by the
operation as a bundle conforming to the **real STIX 2.1
specification**, and serves it through a **minimal TAXII 2.1
server**.

## Why No Library (Raw JSON)

The `stix2` Python library is a common tool, but this module
deliberately produces raw JSON instead — so it works without an
extra dependency, and so "what's actually underneath the STIX format"
stays directly visible. The JSON produced is fully compliant with the
OASIS STIX 2.1 specification (object types, required fields, ID
format `type--uuid`) and can be handed to a real STIX parser (e.g.
`stix2.parse()`).

## STIX Objects Produced

| Type | Count | Content |
|---|---|---|
| `vulnerability` | 3 | CVE-2021-41773, CVE-2021-42013, CVE-2021-4034 |
| `attack-pattern` | 3 | T1190, T1059, T1548.001 |
| `indicator` | 3 | Path traversal pattern, PwnKit pkexec pattern, AndroxGh0st .env scanning pattern |
| `malware` | 1 | AndroxGh0st (a real, named botnet — see docs/threat-intelligence.md) |
| `relationship` | 8 | SROs linking the objects above together (`indicates`, `exploits`, `uses`) |

## Usage

### Generating the STIX Bundle

```bash
python3 intel-export/stix_export.py
```

Output: `intel-export/output/obsidian_protocol_bundle.stix2.json`

### Starting the TAXII Server

```bash
python3 intel-export/taxii_server.py
```

```bash
# Discovery
curl http://localhost:8888/taxii2/

# Collections
curl http://localhost:8888/taxii2/api/collections/

# STIX objects
curl http://localhost:8888/taxii2/api/collections/obsidian-protocol-collection-001/objects/
```

### Consuming It With a Real STIX Client (Example)

```python
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v21 import Collection

collection = Collection("http://localhost:8888/taxii2/api/collections/obsidian-protocol-collection-001/")
source = TAXIICollectionSource(collection)
vulns = source.query([Filter("type", "=", "vulnerability")])
```

> Note: the example above requires the `stix2` and `taxii2-client`
> libraries (`pip install stix2 taxii2-client`); this repository
> itself does not depend on them.

## Known Limitation

`taxii_server.py` implements only TAXII 2.1's read-only "Get Objects"
flow. Writing (POST /objects/), filtering query parameters
(`added_after`, `match[type]`, etc.), and authentication are not
supported — these are features production TAXII servers (e.g.
OpenCTI, EclecticIQ) cover that this reference implementation does
not.
