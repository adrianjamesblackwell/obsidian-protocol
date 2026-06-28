# BLACKWELL KNOWLEDGE GRAPH (BKG) v1.0

### Entity-relationship view, derived as a projection of the Evidence Graph — not a second source of truth

## Positioning

[`evidence-graph/README.md`](../evidence-graph/README.md) is explicit
that BEG's nodes are *claims*, not entities, and that the
entity-relationship view ("this host relates to this CVE relates to
this user") is something you derive from BEG, not a parallel
structure you maintain separately. BKG is that derivation.

This matters for a concrete reason: if BKG were updated independently
of BEG, the two could drift — BKG could claim a relationship that the
evidence no longer supports. By computing BKG as a pure projection
(`build_knowledge_graph(graph)` takes a graph and returns entities +
edges, with no separate mutable state), BKG is always exactly as
current as the evidence it was derived from, and "why does the graph
believe this relationship" always resolves back to a real BEG node.

## How entities are extracted

| Source node kind | Entities extracted |
|---|---|
| `RAW_EVENT` | host, user, src_ip, cve (whichever are present) |
| `INDICATOR` | cve, vendor |
| `ASSERTION` | actor (host/user/ip), each CVE in the chain |
| `CONCLUSION` | cve (for BRS-style conclusions) |

Any two entities extracted from the **same** evidence node get a
`RELATED_TO` edge, with `strength = mean(weight of licensing nodes)`
and a `licensing_nodes` list — the exact BEG nodes that justify the
relationship.

## Usage

```bash
python3 blackwell-core/knowledge-graph/knowledge_graph.py
```

Output: `output/knowledge_graph.json`

## Known limitations

1. **No entity resolution.** `user:1000` and what that account becomes
   after privilege escalation are different entities, not merged —
   the same identity-resolution gap BCA documents at the correlation
   level.
2. **Fixed, hand-coded extraction schema per node kind.** A new
   telemetry source with a different attribute shape needs a schema
   update here, not automatic discovery.
3. **Single undifferentiated `RELATED_TO` relation type.** A richer
   typed schema (`HOSTED_ON`, `EXPLOITED_BY`, …) is possible future
   work, but this project's current lab data doesn't yet exercise
   enough relationship variety to make that distinction meaningfully
   different from `RELATED_TO` in practice — so it wasn't added just
   to look more complete.
