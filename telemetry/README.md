# TELEMETRY PIPELINE
### OBSIDIAN PROTOCOL / Hybrid Data Collection and Timeline Construction

This module collects the raw telemetry produced by the range's attack
chain (VECTOR-I + VECTOR-II) from **three different sources** and
merges it into a single normalized timeline.

## Architecture: why hybrid

| Source | Layer | What it catches | Limitation |
|---|---|---|---|
| **Apache access log** | Application | VECTOR-I (path traversal, RCE attempts) | HTTP layer only |
| **auditd** | Userspace audit | VECTOR-II (pkexec syscall, argc=0) | Some variants can create a gap, since pkexec's own audit code can be bypassed |
| **eBPF (bpftrace)** | Kernel | VECTOR-II (execve syscall, directly from the kernel) | Requires extra capabilities/setup |

The reason we use **both** auditd and eBPF: auditd is easier to set
up and already present in most real-world environments, but because
PwnKit's exploit path runs **ahead of** pkexec's normal audit/logging
code (see the VECTOR-II analysis in `docs/walkthrough.md`), auditd can
sometimes catch nothing at all. eBPF sees the syscall directly at the
kernel level, closing that gap. Combining the two sources illustrates
why real EDR architectures (CrowdStrike Falcon, SentinelOne) generally
use more than one telemetry layer.

## Operating modes

### Offline (default) — from existing log files

Save the real logs produced while following `docs/walkthrough.md`,
then feed them to the pipeline:

```bash
# Pull logs out of target-49
docker cp obsidian-target-49:/usr/local/apache2/logs/access_log telemetry/sample-data/my_apache.log
docker exec obsidian-target-49 ausearch -k pkexec_exec --format raw > telemetry/sample-data/my_auditd.log

# Merge
python3 telemetry/build_timeline.py \
  --auditd telemetry/sample-data/my_auditd.log \
  --apache telemetry/sample-data/my_apache.log
```

### Live mode — directly from the container

```bash
python3 telemetry/build_timeline.py --live
```

This pulls logs directly from `obsidian-target-49` via `docker exec`
— can be run during or right after the operation.

### eBPF live monitoring (optional, advanced)

```bash
# Inside the target-49 container (requires CAP_BPF/CAP_SYS_ADMIN):
bpftrace telemetry/collectors/pwnkit_ebpf_trace.bt > /tmp/ebpf_output.jsonl &

# Run VECTOR-II, then:
python3 telemetry/parsers/ebpf_parser.py /tmp/ebpf_output.jsonl
```

> **Note:** `bpftrace` is not installed in the container by default
> and generally requires `--privileged` or at least the `CAP_BPF` +
> `CAP_PERFMON` capabilities. This is acceptable in an isolated lab
> environment, but the answer to "why does this need extra
> permissions": eBPF programs are loaded into the kernel, which is
> outside a normal container's default permission set.

## Output format

All parsers normalize into the `ObsidianEvent` format defined in
`telemetry/schemas/event_schema.py`. The unified output is
`telemetry/output/unified_timeline.ndjson` — NDJSON (one JSON event
per line), read by the Purple Team module and the Risk Engine.

## File structure

```
telemetry/
├── schemas/
│   └── event_schema.py        # Common ObsidianEvent data model
├── parsers/
│   ├── auditd_parser.py        # auditd -> ObsidianEvent
│   ├── apache_log_parser.py    # Apache access log -> ObsidianEvent
│   └── ebpf_parser.py          # bpftrace JSON -> ObsidianEvent
├── collectors/
│   └── pwnkit_ebpf_trace.bt    # Live eBPF monitor (bpftrace script)
├── sample-data/                 # Test/sample logs (real format, fake content)
├── output/
│   └── unified_timeline.ndjson  # Unified, time-sorted output
└── build_timeline.py            # Orchestrator (offline + live mode)
```
