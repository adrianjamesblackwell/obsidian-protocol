# PURPLE TEAM VALIDATION LAYER
### OBSIDIAN PROTOCOL / Attack -> Detection -> Validation Loop

This module automatically matches red team (attack) actions against
the blue team's (WARDEN module's) telemetry signals and produces a
**Detection Coverage** report.

## How it works

```
GROUND TRUTH (attack_log.json)          TELEMETRY (unified_timeline.ndjson)
  "10:15:32 - performed path traversal"  <->  "10:15:32 - Apache log: traversal pattern"
  "10:18:00 - ran PwnKit"                <->  "10:18:05 - auditd: pkexec argc=0"
                    |                                    |
                    +------------ validate.py -----------+
                                   |
                                   v
                    Detection Coverage Report
                    (detected / missed / latency)
```

## Usage

### 1. Fill in the ground truth file

While following `docs/walkthrough.md`, note down the EXACT MOMENT you
perform each step. Copy `attack_log_template.json` and fill it in with
your own timestamps:

```bash
cp purple-team/attack_log_template.json purple-team/my_attack_log.json
# Edit with the real timestamps from your own operation
```

> **Tip:** Before running each exploit step, note the current UTC time
> with `date -u +%Y-%m-%dT%H:%M:%S+00:00`. This guarantees the
> accuracy of your ground truth.

### 2. Collect telemetry

```bash
python3 telemetry/build_timeline.py --live
# or in offline mode (see telemetry/README.md)
```

### 3. Run validation

```bash
python3 purple-team/validate.py purple-team/my_attack_log.json
```

## Interpreting the output

- **Detected (%):** What fraction of total attack steps matched a
  WARDEN signal.
- **Average detection latency:** The gap between the attack moment and
  when the detection signal was produced (a simplified MTTD — Mean
  Time To Detect — approach).
- **Missed steps:** These fall into two categories:
  1. **A real detection gap** — a Sigma rule in WARDEN doesn't cover
     this step, the rule needs work.
  2. **An expected miss** — the step itself (e.g. a plain recon GET
     request) already looks "harmless," and no signature firing is
     normal. In this case the miss isn't a bug, it's an
     **observability limit** — in real SOC environments, recon
     traffic generally can't be separated from noise either.

## Known limitation (stated for transparency)

The matching algorithm works on the VECTOR + CVE label. This is
simpler than the network/process/time-based correlation a real SIEM
correlation engine performs. A deliberate design choice: the goal
isn't a production-grade correlation engine, but a readable reference
implementation that demonstrates how this methodology works.

## Output

`purple-team/output/coverage_results.json` — used as input by the
**Risk Scoring Engine** and the **reporting engine**.
