# ADVERSARY EMULATION QUALITY SCORE
### OBSIDIAN PROTOCOL / Measuring the Quality of a Red Team Operation

## Problem

Organizations run Red Team operations but rarely measure the
**quality** of the operation itself. "We ran a Red Team exercise" is
not the same claim as "we ran a *good* Red Team exercise."

## Four Dimensions

| Dimension | Measures | Source |
|---|---|---|
| Attack Diversity | How many distinct MITRE techniques were used | Correlation Engine |
| MITRE Matrix Coverage | Those techniques as a fraction of all 216 | Correlation Engine |
| Noise Level | How "focused" the operation was (few, high-confidence actions) | Correlation Engine confidence scores |
| Detection Success | How much of this emulation WARDEN actually caught | Purple Team |

## This Project's Own Grade: "C"

OBSIDIAN PROTOCOL's own emulation score comes out deliberately low
(1.39% Coverage, overall grade "C") — this isn't a bug, it's **an
honest measurement**: the project covers only 2 CVEs / 3 techniques,
which is a small fraction of MITRE's full 216-technique matrix. Rather
than inflating its own scope to produce an artificially high grade,
this engine reports the real ratio.

## Usage

```bash
python3 emulation-score/emulation_score.py
```

## Known Limitation

`compute_noise_level` is a simple confidence-ratio heuristic — a real
"noise" measurement (e.g. how many distinct alerts the operation
triggered in a SIEM, analyst triage time) would require a much richer
dataset. This engine uses a simpler proxy derived from the existing
Correlation Engine confidence data.
