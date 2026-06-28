# Contributing to OBSIDIAN PROTOCOL

Thanks for considering a contribution. This is a single-maintainer
research/portfolio project (part of Blackwell Intelligence), so the
bar for merging is "does this make the evidence-reasoning pipeline
more correct, more honest about its limitations, or more useful" -
not "does this add a feature for its own sake."

## Before you start

For anything beyond a small fix, please open an issue first describing
what you want to change and why. This avoids duplicated work and lets
us agree on direction before you invest time. See the open
[issues](../../issues) for the current roadmap - `BCA-v2`, a benign
traffic generator, multi-host scenarios, STIX Sightings support, and
adaptive risk weighting are all explicitly tracked there.

## Ground rules

- **No fabricated metrics.** Every number any module produces must
  come from that module's own real computation against real (lab)
  data. If a metric can't be honestly computed yet, document it as a
  limitation in `docs/research-findings.md` instead of approximating
  it silently.
- **Limitations stay visible.** If you add a module or extend an
  existing one, add or update its "known limitations" section in the
  relevant `README.md`. Claims that aren't backed by what the code
  actually measures don't get merged.
- **Isolated lab only.** All attack/exploitation code must run only
  inside the `docker-compose.yml` range. Nothing in this repo should
  be capable of being pointed at a real or third-party host.
- **Every module keeps working standalone.** Blackwell Core sits on
  top of the 17 legacy modules; it must never become a hard
  dependency for any of them.

## Development setup

```bash
git clone https://github.com/adrianjamesblackwell/obsidian-protocol.git
cd obsidian-protocol
./setup.sh
```

See the main [README](README.md) for the full end-to-end run order
and [`docs/walkthrough.md`](docs/walkthrough.md) for the guided
operation log.

## Submitting changes

1. Fork the repo and create a branch from `main`.
2. Make your change. Keep commits scoped and the message descriptive.
3. If you touched a module's logic or output format, regenerate its
   `output/` artifacts and confirm `reporting/generate_all_reports.py`
   still runs end to end.
4. Update the relevant module `README.md` (formula, limitations) if
   behavior changed.
5. Open a pull request describing what changed and why, referencing
   the issue it addresses.

## Code style

- Python 3.12, standard library where reasonable; keep new
  third-party dependencies to a minimum and justify them in the PR.
- Match the existing module structure: a `README.md` explaining the
  formula/format and limitations, a script, and an `output/` directory
  (gitignored - see `examples/` for committed sample output instead).
- Sigma/YARA rules go in `detection/`, with MITRE ATT&CK technique IDs
  noted in the rule metadata.

## Reporting bugs vs. proposing features

- **Bugs** (incorrect score, broken pipeline step, wrong MITRE
  mapping): open an issue with steps to reproduce.
- **Features**: open an issue first. Check the roadmap issues listed
  above - your idea may already be tracked, or may be deliberately
  out of scope (see each module's "what this does NOT claim" section).

## Code of conduct

Be direct, be specific, and back claims with evidence - the same
standard this project holds its own output to. Disagreement on
technical approach is welcome; bad-faith or abusive conduct isn't.
