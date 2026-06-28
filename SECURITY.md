# Security Policy

## Scope

OBSIDIAN PROTOCOL is an educational / portfolio project. It
reproduces known, publicly disclosed, and patched CVEs
(CVE-2021-41773, CVE-2021-42013, CVE-2021-4034) strictly inside an
isolated, offline Docker lab defined in `docker-compose.yml`. No part
of this repository is intended to run against, or is tested against,
any live, third-party, or internet-facing system.

This policy covers the code and detection content in this repository
itself (Python modules, Sigma/YARA rules, Docker images, reporting
pipeline) - not the CVEs it reproduces, which are already public,
patched, and tracked upstream by NVD / CISA KEV.

## Supported versions

| Version | Supported |
| :--- | :--- |
| `main` (latest) | Yes |
| Tagged releases | Best effort |

This is a single-maintainer research project, not a production
security product. There is no SLA on patches.

## Reporting a vulnerability

If you find an issue in this repository's *own* code - for example,
a way the detection pipeline, reporting scripts, or Docker setup
could be made to do something unintended, or a real secret/credential
accidentally committed - please report it privately rather than
opening a public issue:

1. Open a [GitHub Security Advisory](../../security/advisories/new)
   for this repository, **or**
2. Contact [Adrian James Blackwell](https://github.com/adrianjamesblackwell)
   directly via GitHub.

Please include:
- A clear description of the issue and its impact
- Steps to reproduce (commands, file paths, payloads)
- Whether the issue is in the platform code itself, or in one of the
  reproduced CVEs (the latter is already public and doesn't need
  coordinated disclosure)

You should expect an initial response within 7 days.

## Out of scope

- The underlying CVEs themselves (CVE-2021-41773, CVE-2021-42013,
  CVE-2021-4034) - these are years-old, patched, and already public.
  Report findings about the *upstream* software (Apache HTTPD,
  polkit) to those projects, not here.
- Findings that require running this lab against a target other than
  the one defined in `docker-compose.yml`.
- Theoretical issues with no practical exploit path inside the lab's
  isolated network.

## Disclosure

Confirmed issues in this repository's own code will be fixed and
credited in the relevant release notes. There is no bug bounty.
