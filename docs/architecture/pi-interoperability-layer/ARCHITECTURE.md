"""pi-interoperability-layer

Deterministic interoperability layer for governed semantic runtimes.

## Architecture

### Core Modules

| Module | Responsibility |
|--------|--------------|
| `contracts` | Canonical artifact contracts, versioning, fingerprinting |
| `schema_registry` | Versioned schema authority, compatibility validation |
| `execution` | Event-sourced execution layer, replay ledger |
| `interfaces` | Runtime interface governance, worker envelopes, messaging |
| `blast_radius` | Deterministic topology propagation scoring |
| `cicd` | GitHub Actions integration, PR gating, policy hooks |

### Design Principles

- **deterministic execution** — all hashes, scores, and decisions are reproducible
- **bounded semantics** — caps on events, ledgers, dependencies, depth
- **replay-governed authority** — every event chain is integrity-verifiable
- **evidence-bound claims** — every violation references exact rule and provenance
- **fail-closed behavior** — missing evidence blocks, never passes
- **centralized governance** — schema registry is single source of contract truth
- **append-only epistemic promotion** — ledgers and evolution logs only grow
- **non-self-modifying workers** — no runtime mutates its own contract definitions
- **no recursive autonomy** — no runtime spawns or governs itself
- **no probabilistic inference** — no scoring uses probability or LLM calls
- **validation before mutation** — compatibility checks precede any schema change

### Pipeline Position

```
pi-semantic-recon          (Observe)
      |
pi-semantic-diff            (Compare)
      |
pi-semantic-validator       (Govern)
      |
pi-interoperability-layer   (Stabilize)  <-- current position
      |
pi-blast-radius             (Estimate Risk)
```

The interoperability layer sits above all runtimes and provides:
1. Frozen artifact contracts that recon, diff, validator, and blast-radius all consume
2. Schema registry that prevents cross-runtime drift
3. Event-sourced execution substrate that makes every pipeline step replayable
4. Runtime messaging that preserves provenance across boundaries
5. CI/CD gating that enforces all of the above before code reaches main

### Artifact Contracts

Every artifact type has a frozen `ArtifactContract`:
- Semantic version (major.minor.patch-label)
- Schema reference (Pydantic model or JSON Schema URI)
- Fingerprint fields (which fields participate in content hash)
- Serialization rules (canonical JSON: sorted keys, no whitespace variance)
- Backward compatibility statement

`ArtifactFingerprint` provides deterministic identity:
- SHA-256 of canonical payload
- Contract hash
- Provenance hash chain
- Generator runtime ID

### Schema Registry

`ContractRegistry` is the centralized authority:
- Register contracts with semantic versions
- Compute registry hash for determinism verification
- Compatibility check: same major = backward compatible
- Evolution log: append-only record of all schema migrations

`SchemaValidator` provides:
- `validate_compatibility(contract_id, candidate_version)`
- `validate_migration_path(from_version, to_version)`
- Replay-safe migration enforcement

### Event-Sourced Execution

`ReplayLedger` is an append-only hash chain:
- Every event has `sequence_number`, `previous_hash`, `event_hash`
- Ledger integrity verified by recomputing hashes
- Deterministic replay slices by sequence range
- Bounded: max events per ledger, max ledger count

`ExecutionEngine` manages active and completed ledgers:
- `open_ledger(id)` → `emit(event)` → `close_ledger(id)`
- `verify_ledger(id)` checks chain integrity
- `replay_ledger(id, from, to)` for deterministic replay

### Runtime Interfaces

`WorkerInputEnvelope` and `WorkerOutputEnvelope` standardize all runtime I/O:
- Identity hashes for deterministic verification
- Provenance chain continuity
- Strict mode flag (fail-closed)
- Schema version requirement

`RuntimeMessage` provides cross-runtime messaging:
- Source/target runtime identification
- Provenance chain with integrity hash
- Replay-safe routing decisions

`ReplaySafeRouter` enforces allowed routes:
- `ALLOWED` — target in replay-safe list
- `REQUIRES_REPLAY_VERIFICATION` — target allowed but not replay-safe
- `FORBIDDEN` — target not in allowed list

### Blast Radius

`BlastRadiusEngine` computes deterministic topology impact:
- `dependency_expansion` — new nodes reachable from changed node
- `topology_complexity_delta` — change in complexity score
- `auth_surface_expansion` — new auth fields introduced
- `replay_scope_expansion` — growth of replay-affected nodes
- `side_effect_bound_delta` — change in side-effect-bound endpoint count

Bounded limits prevent unbounded growth:
- max dependencies, fanout, graph depth
- max auth fields, replay scope nodes
- max drift scores

### CI/CD Integration

`PRGateConfig` evaluates merge gates deterministically:
- Required validation passes must all return True
- Required artifacts must be present and fingerprinted
- Replay verification required by default
- Policy drift check required by default
- Fail-closed: any missing requirement blocks merge

`ReplayValidationGate` enforces replay safety in CI:
- Correct ledger ID
- Minimum verified sequence
- Allowed replay class
- Sandbox required
- Production replay prohibited

`PolicyEnforcementHook` attaches to pipeline stages:
- PRE_MERGE, POST_MERGE, PRE_DEPLOY, POST_DEPLOY
- Required validations and contracts
- Notification targets on failure

### CLI Usage

```bash
# Check schema compatibility
pi-contracts check-compat \
  --registry-path ./registry/ \
  --contract-id SemanticIRTrace \
  --candidate-version 1.1.0

# Verify replay ledger integrity
pi-contracts verify-ledger --ledger-path ./ledger.json

# Evaluate PR gate
pi-contracts eval-gate \
  --gate-config ./gate.json \
  --results ./results.json
```

### Invariants Preserved

All existing invariants from pi-semantic-validator are preserved:
- deterministic execution
- bounded semantics
- replay-governed authority
- evidence-bound claims
- fail-closed behavior
- centralized governance
- append-only epistemic promotion
- non-self-modifying workers
- no recursive autonomy
- no probabilistic quorum
- no speculative promotion
- validation before mutation

No LLM calls. No inference. No probabilistic scoring.
Infrastructure-grade determinism only.
"""
