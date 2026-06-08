# pi-semantic-diff Architecture

## Overview

pi-semantic-diff is a **deterministic behavioral delta runtime**. It consumes two
semantic snapshots (baseline and modified) and produces an evidence-bound,
deterministic diff report.

**Not an AI agent.** Not autonomous. No inference. No LLM calls.

## Pipeline Position

```
pi-semantic-recon      (Observe)      → semantic snapshots
     |
pi-semantic-diff       (Compare)      → behavioral delta reports
     |
pi-semantic-validator  (Govern)       ← consumes diff reports
     |
pi-semantic-radius     (Estimate Risk)← consumes topology changes
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
| `models.py` | Immutable delta artifacts: EndpointDelta, DependencyDelta, AuthDelta, ReplaySurfaceDelta, SemanticDiffReport |
| `deltas.py` | Pure delta computation functions: endpoint, dependency, auth, replay surface |
| `runtime.py` | DiffRuntime: fixed-order pass execution with bounded limits |
| `violations.py` | Deterministic violation builder with provenance chains |
| `cli.py` | `pi-semantic-diff diff --baseline --modified --output` |

## Diff Passes (Fixed Order)

1. **Endpoint Deltas** — added/removed/changed endpoints, field changes, type mutations
2. **Dependency Deltas** — edge additions/removals, node lifecycle changes
3. **Auth Deltas** — invariant additions/removals, rotation class changes, binding drift
4. **Replay Surface Deltas** — replay class degradation, sandbox requirement changes

## Scoring

All scores are deterministic and bounded [0, 1]:

- `structural_delta_score` — topology change magnitude
- `semantic_delta_score` — field/type/contract change magnitude
- `drift_score` — composite escalation metric

## Bounded Execution

DiffBounds caps:
- max_endpoint_deltas = 512
- max_dependency_deltas = 512
- max_auth_deltas = 256
- max_replay_deltas = 512

Excess deltas are silently truncated. Violation is evidence-bound, not probabilistic.

## Output Contract

SemanticDiffReport is consumed by pi-semantic-validator's mutation_drift pass
and pi-semantic-radius's topology expansion pass.
