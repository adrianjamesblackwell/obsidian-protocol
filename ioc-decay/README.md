# IOC CONFIDENCE & DECAY ENGINE
### OBSIDIAN PROTOCOL / The IOC Aging Problem

## Problem

IP, domain, and hash IOCs age quickly — today's malicious IP can be a
legitimately reassigned cloud address three months from now.
Organizations accumulate IOC lists but rarely prune them, which
steadily increases the false-positive rate over time.

## Formula

```
confidence = 100 x decay_factor(age) x frequency_boost x source_boost

decay_factor(age) = 0.5 ^ (age_days / half_life)        [half_life = 90 days]
frequency_boost    = 1 + log10(frequency) x 0.3          [log-scale, prevents inflation]
source_boost        = 1 + min(source_count - 1, 5) x 0.15
```

**Design rationale:** exponential decay reflects real-world behavior
— an IOC's reliability doesn't fall off linearly over time, it drops
along a curve that starts fast and slows down. `frequency_boost` is
log-scaled because seeing an IOC 1,000 times doesn't make it "10x"
more trustworthy than seeing it 100 times. `source_boost` is weighted
more heavily than frequency because independent corroboration is a
stronger signal than repeated observation from the same vantage
point.

## Confidence Bands

| Band | Score | Action |
|---|---|---|
| ACTIVE | ≥70 | Suitable for operational use |
| AGING | 40-69 | Re-validation recommended |
| STALE | 15-39 | Should not be used in active blocking |
| EXPIRED | <15 | Should be removed from the blocklist |

## Usage

```bash
python3 ioc-decay/ioc_decay.py
```

## Known Limitation

`half_life=90 days` is a fixed constant and doesn't vary by IOC type
— in reality, an IP address ages at a very different rate than a file
hash (IPs get reassigned; cryptographic hashes never become "wrong").
A production system should use a separate `half_life` parameter per
`ioc_type` — this project uses a single constant for simplicity.
