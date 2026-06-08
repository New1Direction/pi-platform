# pi-semantic-validator

## Deterministic Semantic Governance Runtime

**Version:** 0.1.0  
**Role:** Pipeline Node 2 (Governance)  
**Predecessor:** pi-semantic-recon (Observe)  
**Successor:** pi-blast-radius (Estimate Risk)

---

## Core Principle

> Semantic cognition derives structure.  
> Infrastructure enforces truth.

LLMs and semantic extraction engines MAY assist discovery and mapping.  
They MUST NOT become enforcement authority.

Governance, validation, replay authority, and mutation control remain  
deterministic infrastructure concerns.

---

## Architectural Role

Pipeline progression:

```
Observe  →  Compare  →  Govern  →  Estimate Risk

pi-semantic-recon  →  pi-semantic-diff  →  pi-semantic-validator  →  pi-blast-radius
```

The validator consumes:

- Semantic graph artifacts from `pi-semantic-recon`
- Behavioral delta graphs from `pi-semantic-diff`
- `architecture-policy.json`

It outputs:

- `PASS` / `FAIL` / `INDETERMINATE`
- Bounded deterministic violations
- Provenance-linked evidence
- Replay safety constraints
- Blast-radius violations
- Policy drift reports

---

## Preserved Invariants

| Invariant | Enforcement |
|-----------|-------------|
| Deterministic execution | Pure functions, fixed pass order, no external calls |
| Bounded semantics | `ValidationBoundsConfig` caps all loops and collections |
| Replay-governed authority | Violations reference replay evidence where applicable |
| Evidence-bound claims | Every violation contains exact rule, provenance chain, file/module evidence, semantic path |
| Centralized governance | `architecture-policy.json` is the single source of truth |
| Fail-closed | Unmatched / unclassified artifacts are violations when `global_fail_closed=True` |
| Append-only epistemic promotion | Reports are immutable; violations are never deleted |
| Non-self-modifying workers | Passes are pure functions; no state mutation |
| No recursive autonomy | No worker spawns other workers |
| No probabilistic quorum | No majority voting; strict deterministic rule matching |
| No speculative promotion | Violations are only produced by explicit rule matches |
| Validation before mutation | Mutation assistance only permitted AFTER governance layers complete |

---

## Validation Passes

### 1. Boundary Validation

- **Forbidden trust boundary crossings:** `DependencyGraph` edges crossing `FORBIDDEN` zone boundaries.
- **Isolated database enforcement:** State writers must match `allowed_writers` in their layer.
- **Unauthorized state writers:** Stateful mutations in layers without write authorization.

### 2. Layer Validation

- **Forbidden imports:** `DependencyGraph` edges violating `LayerRule` `FORBIDDEN` actions.
- **Runtime layering violations:** Endpoints not matching any layer definition (when fail-closed).
- **Backend/frontend inversion detection:** Downstream layer appears in upstream `forbidden_importers`.

### 3. Mutation Drift Validation

- **READ_ONLY → STATEFUL_MUTATION detection:** Method-based classification mismatch against `MutationRule`.
- **Destructive mutation escalation:** `DELETE` / `PUT` lacking `REPLAY_UNSAFE` classification where required.
- **Auth requirement drift:** Stateful mutations without matching `AuthInvariant` coverage.

### 4. Replay Safety Validation

- **Production replay prohibitions:** Endpoints with `production_replay_prohibited=True` lacking replay confirmation.
- **Sandbox-required routes:** Stateful mutations not in `sandbox_replayable_mutations` list.
- **Replay mutation classifications:** Effective replay class must match `required_replay_class`.

### 5. Blast Radius Validation

- **Dependency expansion limits:** Per-endpoint dependency counts, cross-service edge caps.
- **Topology complexity growth:** Fanout limits, graph depth bounds, complexity score ceilings.
- **Auth surface expansion:** Auth field counts per endpoint, unconfirmed binding thresholds.
- **Replay propagation scope growth:** Side-effect-bound endpoint caps, replay scope node limits.

---

## Policy Schema

`architecture-policy.json` is the constitutional rule set.

```json
{
  "policy_id": "prod-policy-001",
  "policy_version": "1.0.0",
  "global_fail_closed": true,
  "trust_zones": [...],
  "trust_boundary_rules": [...],
  "layers": [...],
  "layer_rules": [...],
  "mutation_rules": [...],
  "replay_rules": [...],
  "blast_radius_limits": {...},
  "state_writer_rules": [...],
  "forbidden_import_rules": [...]
}
```

Rules are **not learned**. They are **declared**.

---

## Runtime Execution Model

```
ValidatorRuntime
  ├── load policy
  ├── load artifacts
  ├── compute hashes (determinism / replay)
  ├── for each pass in fixed order:
  │     ├── execute pass with bounded iteration
  │     ├── collect violations (truncated at max_violations_per_pass)
  ├── assemble report
  └── emit PASS / FAIL / INDETERMINATE
```

All passes are **pure functions**:

```python
f(envelope: Dict[str, Any]) -> WorkerResponse
```

The runtime owns state transitions. Passes only propose violations.

---

## Violation Model

Every violation contains:

| Field | Description |
|-------|-------------|
| `violation_id` | Unique deterministic identifier |
| `rule` | Exact policy rule identifier |
| `pass_name` | Validation pass that emitted it |
| `severity` | `WARNING` / `ERROR` / `CRITICAL` |
| `context.endpoint` | Affected endpoint path |
| `context.field_path` | Affected semantic field |
| `context.provenance_chain` | Artifact and trace references |
| `context.file_evidence` | Source file evidence |
| `context.module_evidence` | Module evidence |
| `context.replay_evidence` | Replay execution references |
| `action_taken` | `HALT` or `LOG` |

---

## Bounded Execution

`ValidationBoundsConfig` enforces hard limits:

- `max_violations_per_pass`: 128
- `max_endpoints_per_trace`: 1024
- `max_edges_per_graph`: 512
- `max_fields_per_endpoint`: 256
- `max_policy_rules`: 4096
- `max_blast_radius_depth`: 6
- `max_replay_scope_nodes`: 256
- `max_mutation_chain_length`: 32
- `max_provenance_depth`: 16

Exceeding any bound produces a `BOUNDED_EXECUTION_VIOLATION_LIMIT_EXCEEDED` violation.

---

## CI/CD Integration

```bash
# Validate a recon output directory against policy
pi-semantic-validator validate \
  --policy architecture-policy.json \
  --artifacts recon-output/ \
  --output validation-report.json \
  --strict

# Exit codes
# 0 → PASS
# 1 → FAIL or strict-mode warnings
```

---

## Design Philosophy

The validator is **NOT an AI agent**.

It is a **deterministic semantic governance worker**.

- No inference
- No LLM calls
- No probabilistic scoring
- No auto-remediation
- No speculative causality
- No runtime state mutation
- No self-modification

All behavior is derived from explicit policy rules applied to explicit artifacts.

---

## File Structure

```
pi-semantic-validator/
  pyproject.toml
  README.md
  src/
    pi_semantic_validator/
      __init__.py
      models.py          # Shared primitives and report models
      policy.py          # architecture-policy.json schema and loader
      runtime.py         # Core validator runtime
      violations.py      # Deterministic violation builder
      pipeline.py        # High-level pipeline integration
      cli.py             # Command-line interface
      passes/
        __init__.py
        boundary.py      # Trust boundary validation
        layer.py         # Layering validation
        mutation_drift.py # Mutation drift validation
        replay_safety.py  # Replay safety validation
        blast_radius.py   # Blast radius validation
  tests/
    test_policy.py
    test_passes.py
    test_runtime.py
    test_violations.py
    test_cli.py
  docs/
    ARCHITECTURE.md
```
