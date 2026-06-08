# pi-semantic-radius Architecture

## Overview

pi-semantic-radius is a **deterministic propagation risk runtime**. It consumes
two topology graphs (baseline and modified) and produces an evidence-bound,
deterministic risk report with bounded blast radius metrics.

**Not an AI agent.** Not autonomous. No inference. No LLM calls.

## Pipeline Position

```
pi-semantic-recon      (Observe)      → semantic snapshots
     |
pi-semantic-diff       (Compare)      → behavioral delta reports
     |
pi-semantic-validator  (Govern)       ← consumes diff + policy
     |
pi-semantic-radius     (Estimate Risk)← consumes topology evolution
```

## Core Invariants

- deterministic execution
- bounded semantics
- replay-governed authority
- evidence-bound claims
- fail-closed behavior
- append-only epistemic promotion
- non-self-modifying workers
- no recursive autonomy
- no probabilistic inference
- validation before mutation

## Module Structure

| Module | Responsibility |
|--------|--------------|
| `models.py` | Topology primitives, RiskScore, RiskReport, PassResult |
| `engine.py` | BlastRadiusEngine: bounded graph traversal, complexity scoring, limit evaluation |
| `passes/propagation_risk.py` | Dependency expansion detection, complexity delta violations |
| `passes/topology_expansion.py` | Node/edge/fanout/depth growth detection |
| `passes/auth_boundary.py` | Auth surface widening, field count limits |
| `passes/replay_hazard.py` | Replay class degradation, scope propagation |
| `passes/mutation_impact.py` | Side-effect-bound expansion, mutation class escalation |
| `runtime.py` | RadiusRuntime: fixed-order pass orchestration |
| `cli.py` | `pi-semantic-radius analyze --baseline --modified --output` |

## Pass Order (Fixed, Deterministic)

1. **propagation_risk** — dependency expansion, complexity delta
2. **topology_expansion** — node/edge/fanout/depth growth
3. **auth_boundary** — auth field widening
4. **replay_hazard** — replay class degradation, scope limits
5. **mutation_impact** — mutation escalation, side-effect-bound growth

## Blast Radius Metrics

All metrics are deterministic integers or floats:

- `dependency_expansion` — newly reachable downstream nodes
- `topology_complexity_delta` — structural complexity change
- `fanout_delta` — max fanout change
- `depth_delta` — max depth change
- `auth_surface_expansion` — new auth fields across graph
- `auth_boundary_widening` — boolean auth expansion flag
- `replay_hazard_spread` — nodes affected by replay degradation
- `replay_propagation_depth` — max replay-reachable depth
- `downstream_mutation_impact` — mutation class escalations in reachable subgraph
- `side_effect_bound_expansion` — side-effect-bound endpoint growth

## Bounded Graph Traversal

- `depth_from()` bounds at depth 32 to prevent infinite recursion on cycles
- `reachable()` uses iterative BFS to prevent stack overflow
- All limits are configurable via `BlastRadiusEngine(...)`

## Default Limits

| Limit | Default |
|-------|---------|
| max_dependencies_per_endpoint | 16 |
| max_cross_service_edges | 64 |
| max_fanout_per_endpoint | 8 |
| max_graph_depth | 6 |
| max_topology_complexity_score | 100.0 |
| max_auth_fields_per_endpoint | 8 |
| max_replay_scope_nodes | 256 |
| max_replay_propagation_depth | 6 |
| max_side_effect_bound_endpoints | 32 |

## Output Contract

RiskReport is consumed by CI/CD gates and downstream governance layers.
`limits_exceeded` contains the names of any violated limits.
`report_hash` provides deterministic replay identity.
