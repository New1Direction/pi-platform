# PI Runtime Specification v1.0
## Deterministic Semantic Execution Kernel — Protocol Reference

**Version:** 1.1.0  
**Date:** 2026-05-18  
**Status:** FINAL (Digital Twin Extension)  
**Scope:** Layers 1–4 of the PI Platform  

---

## Contents

1. [Scope & Conformance](#1-scope--conformance)
2. [Definitions & Notation](#2-definitions--notation)
3. [Architecture Overview](#3-architecture-overview)
4. [Canonical Artifact Lifecycle](#4-canonical-artifact-lifecycle)
5. [Graph Execution Semantics](#5-graph-execution-semantics)
6. [Phase Transition Guarantees](#6-phase-transition-guarantees)
7. [Replay Invariants](#7-replay-invariants)
8. [Deterministic Scheduling Rules](#8-deterministic-scheduling-rules)
9. [Policy Evaluation Order](#9-policy-evaluation-order)
10. [Shard Synchronization Semantics](#10-shard-synchronization-semantics)
11. [Receipt Chain Model](#11-receipt-chain-model)
12. [Trust-Zone Promotion Rules](#12-trust-zone-promotion-rules)
13. [Reference Implementation Mapping](#13-reference-implementation-mapping)
14. [Conformance Test Plan](#14-conformance-test-plan)
15. [Versioning & Maintenance](#15-versioning--maintenance)
16. [Appendices](#16-appendices)

---

## 1. Scope & Conformance

### 1.1 Purpose

This document defines the formal behavioral specification of the PI Platform deterministic semantic execution kernel. It is the single source of truth for:

- How artifacts are created, validated, transformed, and retired
- How execution graphs are interpreted, scheduled, and run
- How replay safety and determinism are guaranteed
- How governance policies are applied
- How cross-shard coordination works
- How trust zones are established and evolve

### 1.2 Conformance Classes

| Class | Description |
|-------|-------------|
| **Core Runtime** | A deterministic execution runtime implementing Layers 1–3 |
| **Console Frontend** | A human interface that produces only `ExplicitCompositionRequest` JSON |
| **Console Backend** | A thin proxy that validates and forwards structured requests |
| **Full Platform** | All 4 layers operating together with correct boundary enforcement |

### 1.3 Normative References

All citations to source code paths in this document refer to the reference implementation under `~/Documents/`:

- `pi-agent-chain/` — Semantic reconstruction pipeline (Layer 2)
- `pi-semantic-diff/` — Differential semantic analysis (Layer 2)
- `pi-semantic-validator/` — Schema and contract validation (Layer 2)
- `pi-semantic-radius/` — Blast radius computation (Layer 2)
- `pi-interoperability-layer/` — Execution fabric, shard coordination, mesh, receipts (Layers 1–3)
- `pi-extension-governor/` — Manifest system, policy engine, trust zones, sandbox (Layer 3)
- `pi-console/` — Human interface boundary (Layer 4)

### 1.4 Hard Invariants (Non-Negotiable)

> **INVARIANT-1:** The core kernel (Layers 1–3) shall never process unstructured natural language, LLM inference, or probabilistic decision-making during any execution path.

> **INVARIANT-2:** The only permitted cross-layer request from Layer 4 to Layers 1–3 is `ExplicitCompositionRequest`, frozen, schema-validated, SHA-256 fingerprinted.

> **INVARIANT-3:** Every artifact, receipt, ledger entry, and policy evaluation shall be deterministic — bit-for-bit reproducible given identical inputs.

> **INVARIANT-4:** Policy evaluation is fail-closed: any ambiguity or missing rule resolves to DENY.

> **INVARIANT-5:** Tenant isolation is absolute: no artifact, receipt, or execution trace may leak across tenant boundaries.

---

## 2. Definitions & Notation

### 2.1 Terms

| Term | Definition |
|------|------------|
| **Artifact** | An immutable, versioned, fingerprinted data object produced by the runtime. All artifacts are Pydantic `BaseModel` instances with `frozen=True`. |
| **Capability** | A declared unit of work with a bounded input/output contract, registered in the Capability Marketplace. |
| **Composition** | A directed acyclic graph (DAG) of `CompositionNode` objects linked by `CompositionEdge` objects, submitted via `ExplicitCompositionRequest`. |
| **Receipt** | A cryptographic record of a single worker execution, chained to previous receipts via SHA-256 hashes. |
| **Ledger** | An append-only chain of `EventRecord` objects with strict monotonic sequence numbering and hash chaining. |
| **Phase** | A named stage in the fixed pipeline order: INGEST → EXTRACT → DIFF → VALIDATE → RISK → GOVERN → EMIT. |
| **Shard** | A deterministic partition of the worker pool assigned by SHA-256 hash of worker_id modulo shard_count. |
| **Trust Zone** | One of: `CORE_TRUSTED`, `GOVERNED_EXTENSION`, `SANDBOX_EXPERIMENTAL`. |
| **Replay** | Re-execution of a recorded event sequence with bit-for-bit output verification. |
| **Determinism Proof** | A SHA-256 hash computed over all output slot fingerprints, enabling replay verification. |

### 2.2 Notation

- `H(x)` — SHA-256 hash of canonical JSON serialization of `x`
- `x → y` — Directed edge from node `x` to node `y`
- `⊥` — Bottom/failure (fail-closed)
- `|S|` — Cardinality of set `S`

---

## 3. Architecture Overview

### 3.1 Layer Responsibilities

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 4: PI CONSOLE (Human Interface Boundary)             │
│  • Natural language input (optional LLM translation)        │
│  • Visual DAG builder                                       │
│  • Simulation preview, compliance dashboards                │
│  • ONLY output: ExplicitCompositionRequest JSON             │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: Capability Economy / Marketplace                  │
│  • ExtensionManifest lifecycle                              │
│  • Policy evaluation & trust-zone enforcement               │
│  • Catalog integration pipeline (7-phase admission)         │
│  • Capability compatibility graph                           │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: Shard-Coordinated Deterministic Execution Fabric  │
│  • Central Orchestrator Kernel (fixed 7-phase pipeline)     │
│  • Artifact Bus (immutable slot-based exchange)             │
│  • Worker Mesh (specialized, bounded, deterministic)        │
│  • Replay Ledger (append-only, hash-chained)                │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1: Multi-Tenant SaaS Control Plane                   │
│  • Tenant registry with quota enforcement                   │
│  • Tenant-scoped policy engine (fail-closed)                │
│  • Execution log & compliance reporting                     │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow

User (natural language) → PI Console Frontend → [Optional LLM Translation] → ExplicitCompositionRequest → PI Console Backend (validation, audit) → PI Core API → Tenant validation → Policy check → Shard scheduling → Phase-locked execution → Receipt chain → Replay ledger.

---

## 4. Canonical Artifact Lifecycle

### 4.1 Artifact Definition

An artifact is a `BaseModel` subclass with `frozen=True` and the following mandatory properties:

1. **Deterministic serialization**: `json.dumps(model_dump(), sort_keys=True, separators=(",", ":"), default=str)`
2. **Schema versioning**: Every artifact declares its contract version via `SchemaVersion(major, minor, patch)`
3. **Fingerprinting**: `ArtifactFingerprint` binds content hash, contract hash, provenance chain, and generator runtime
4. **Immutability**: Once constructed, no field may be mutated. Updates produce new instances via `model_copy(update=...)`

### 4.2 Artifact State Machine

```
    ┌──────────────┐
    │   CREATED    │  — Artifact instance constructed and fingerprinted
    └──────┬───────┘
           │ write()
           ▼
    ┌──────────────┐
    │   FROZEN     │  — compute_fingerprint() called, slot sealed
    └──────┬───────┘
           │ bus.write(slot)
           ▼
    ┌──────────────┐
    │  REGISTERED  │  — Stored in ArtifactBus, version lineage tracked
    └──────┬───────┘
           │ consumed by worker
           ▼
    ┌──────────────┐
    │  REFERENCED  │  — Referenced in receipt provenance chain
    └──────┬───────┘
           │ ledger.append(event)
           ▼
    ┌──────────────┐
    │   ARCHIVED   │  — Retention policy applied, may be purged
    └──────────────┘
```

**Rule ART-1**: No artifact may transition from `FROZEN` back to `CREATED`. Immutability is irreversible.

**Rule ART-2**: An artifact's `content_hash` must match `H(serialized_payload)` at all times. Any mismatch is a `SCHEMA_MISMATCH` panic.

**Rule ART-3**: Artifact evolution follows append-only schema changes tracked in `SchemaEvolutionLog`. Changes are classified as: `ADD_FIELD`, `REMOVE_FIELD`, `TYPE_CHANGE`, `RULE_CHANGE`, `DEPRECATE`.

### 4.3 Supported Artifact Types

The reference implementation defines these canonical artifact types in `ArtifactContract.artifact_type`:

| Type | Producer | Consumer | Immutable |
|------|----------|----------|-----------|
| `SemanticIRTrace` | `EndpointExtractionWorker` | `BoundaryValidationWorker`, diff | Yes |
| `DependencyGraph` | `DependencyExtractionWorker` | `TopologyBuildWorker` | Yes |
| `TopologyGraph` | `TopologyBuildWorker` | `PropagationRiskWorker` | Yes |
| `EndpointDiffReport` | `EndpointDiffWorker` | Merge gate | Yes |
| `BoundaryValidationReport` | `BoundaryValidationWorker` | `MergeGateWorker` | Yes |
| `PropagationRiskReport` | `PropagationRiskWorker` | `MergeGateWorker` | Yes |
| `MergeGateResult` | `MergeGateWorker` | Emitter | Yes |
| `RegistryUpdateReport` | `SnapshotRegistryWorker` | Registry | Yes |
| `SchemaValidationReport` | `SchemaValidationWorker` | Pipeline | Yes |
| `ValidationReport` | Any validator | Governance | Yes |
| `ReplayLedger` | `ExecutionEngine` | Replay system | Yes |
| `EventRecord` | `ExecutionEngine.emit()` | Ledger | Yes |

### 4.4 Artifact Exchange Protocol

All inter-worker artifact exchange flows through the `ArtifactBus`:

1. Worker produces an `ArtifactSlot` via `_run()`
2. Worker calls `slot.freeze()` which computes `fingerprint = H(payload)`
3. Worker calls `bus.write(frozen_slot)` which stores the slot and tracks version lineage
4. Consuming worker calls `bus.read(slot_id)` — receives an immutable reference

**Rule ART-4**: The ArtifactBus shall not permit in-place mutation of stored slots. Every write creates a new slot with a new `slot_id`.

**Rule ART-5**: Slot families are tracked as `{artifact_type}:{producer_worker_id}` enabling lineage traversal.

---

## 5. Graph Execution Semantics

### 5.1 Composition DAG Definition

A composition is a directed acyclic graph `G = (N, E)` where:

- `N` is a set of `CompositionNode` objects
- `E` is a set of `CompositionEdge` objects with `edge_type ∈ {SEQUENTIAL, PARALLEL, CONDITIONAL, FAN_OUT, FAN_IN}`
- `G` must be acyclic: no path from any node to itself

**Rule GRAPH-1**: The core shall reject any composition containing a cycle with status `REJECTED` and reason `dag_contains_cycle`.

**Rule GRAPH-2**: Every node referenced in an edge must exist in `N`. Missing nodes result in `REJECTED` with reason `missing_node_reference`.

**Rule GRAPH-3**: The DAG must be connected: every node must be reachable from at least one root node (a node with no incoming edges).

### 5.2 Node Execution Contract

Each `CompositionNode` declares:

- `runtime`: The target runtime that shall execute this node
- `operation`: The operation type (must be in the runtime's supported set)
- `artifacts`: Input artifact payloads (must be JSON-serializable)
- `bounds`: Per-node deterministic bounds (max_nodes, max_depth, max_fanout, etc.)
- `dependencies`: Node IDs that must complete successfully before this node may start

**Rule NODE-1**: A node may only begin execution after all nodes in its `dependencies` list have produced receipts with `status == SUCCESS`.

**Rule NODE-2**: If any dependency fails, the dependent node shall be marked `BLOCKED` and shall not execute.

**Rule NODE-3**: Node bounds are evaluated before execution. Any bound violation results in `RESOURCE_EXCEEDED` without executing the node body.

### 5.3 Edge Execution Semantics

| Edge Type | Semantics |
|-----------|-----------|
| `SEQUENTIAL` | Target starts after source completes (default) |
| `PARALLEL` | Target may start concurrently with source if no other constraints |
| `CONDITIONAL` | Target starts only if `condition` expression evaluates to true |
| `FAN_OUT` | One source → many targets, all start when source completes |
| `FAN_IN` | Many sources → one target, target starts when all sources complete |

**Rule EDGE-1**: `CONDITIONAL` edges shall only reference deterministic boolean expressions over artifact payload fields. No LLM evaluation. No probabilistic conditions.

### 5.4 Global Bounds

Every `ExplicitCompositionRequest` declares `global_bounds`:

```
max_total_nodes:   64 (hard ceiling)
max_depth:          8 (longest path in DAG)
max_fanout:        16 (max outgoing edges per node)
max_execution_time_ms: 300,000 (5 minutes)
```

**Rule BOUNDS-1**: Global bounds override per-node bounds. The most restrictive bound applies.

**Rule BOUNDS-2**: If any bound is exceeded during simulation, the composition is rejected with `status: REJECTED` and `bounds_violations` populated.

---

## 6. Phase Transition Guarantees

### 6.1 Fixed Phase Order

The execution pipeline follows a strict, immutable phase sequence:

```
INGEST → EXTRACT → DIFF → VALIDATE → RISK → GOVERN → EMIT
```

This order is defined as `PHASE_ORDER` in `CentralOrchestratorKernel`. No runtime may reorder, skip, or insert phases.

### 6.2 Phase-Locked Execution

**Rule PHASE-1**: The orchestrator shall not advance from phase `P_i` to `P_{i+1}` until ALL workers assigned to `P_i` have produced receipts.

**Rule PHASE-2**: If any worker in phase `P_i` produces a receipt with `status ∈ {FAIL, PANIC, SCHEMA_MISMATCH, REPLAY_MISMATCH}`, the phase status is `FAIL`.

**Rule PHASE-3**: If `merge_status == FAIL` and `fail_open == False`, the pipeline terminates immediately. The ledger is closed and no subsequent phases execute.

**Rule PHASE-4**: If a phase is not configured (no `PhaseConfig` exists), an empty `PhaseBoundaryReceipt` with `phase_status: SUCCESS` is appended, and execution continues.

### 6.3 Phase Boundary Receipt

When a phase completes, a `PhaseBoundaryReceipt` is generated:

```
boundary_id: UUID
phase: string
worker_receipt_ids: [sorted receipt IDs]
merged_output_slot_id: string | null
phase_status: PENDING | SUCCESS | FAIL | BLOCKED
previous_boundary_hash: H(previous boundary)
boundary_hash: H(this boundary)
timestamp: ISO-8601 UTC
```

**Rule PHASE-5**: Boundary receipts are chained via `previous_boundary_hash`, forming an immutable phase transition log.

### 6.4 Worker Instantiation Rule

Workers are instantiated deterministically within each phase:

```python
worker_id = f"{phase_name}_{cls.__name__}_{i}"  # i = 0, 1, 2...
```

**Rule PHASE-6**: Worker IDs must be deterministic: re-running the same pipeline with the same `PhaseConfig` must produce identical `worker_id` values.

---

## 7. Replay Invariants

### 7.1 Replay Safety Definition

A computation is **replay-safe** if and only if:

1. Given identical inputs, it produces identical outputs (bit-for-bit)
2. All intermediate states are recorded in an append-only ledger
3. Every state transition is fingerprinted with SHA-256
4. No external non-deterministic sources are consulted (no network, no time-dependent logic, no randomness)

### 7.2 Replay Ledger Structure

The `ReplayLedger` is the authoritative record of execution:

- `ledger_id`: Unique identifier
- `events[]`: Ordered list of `EventRecord` objects
- `ledger_hash`: H(concatenation of all event hashes)
- `first_sequence` / `last_sequence`: Monotonic bounds
- `closed_at`: Timestamp when ledger was sealed

**Rule REPLAY-1**: Event sequence numbers are strictly monotonic: `sequence_number_{i+1} == sequence_number_i + 1`

**Rule REPLAY-2**: Each event's `previous_hash` must equal the `event_hash` of the preceding event. The first event has `previous_hash == ""`.

**Rule REPLAY-3**: `ReplayLedger.verify_integrity()` must return `True` for every closed ledger. A ledger with `verify_integrity() == False` is corrupted and must not be used for replay.

### 7.3 Replay Hash Construction

**Event Hash**:
```
H({
  event_type: string,
  sequence_number: int,
  previous_hash: string,
  payload: canonical_json(payload),
  emitted_by: string,
  emitted_at: ISO-8601
})
```

**Ledger Hash**:
```
H(concat(event_hash_0, event_hash_1, ..., event_hash_n))
```

**Receipt Hash**:
```
H({
  receipt_id: string,
  worker_class: string,
  worker_id: string,
  phase: string,
  input_slot_ids: sorted([string]),
  output_slot_ids: sorted([string]),
  status: string,
  status_detail: string,
  determinism_proof: string,
  resource_usage: {string: float},
  previous_receipt_hash: string,
  timestamp: ISO-8601
})
```

### 7.4 Determinism Proof

Each worker produces a `determinism_proof` after execution:

```
determinism_proof = H(concat(slot.fingerprint for slot in output_slots))
```

**Rule REPLAY-4**: During replay, the determinism proof of the replayed execution must equal the determinism proof recorded in the original receipt. Any mismatch is a `REPLAY_MISMATCH` failure.

### 7.5 Subsystem Determinism Requirements

| Subsystem | Determinism Requirement | Verification Method |
|-----------|------------------------|---------------------|
| Worker scheduling | Same worker_id → same shard assignment | `DeterministicPartitioner.assign()` hash mod |
| Phase ordering | Fixed `PHASE_ORDER` array | Static code reference |
| Artifact serialization | `sort_keys=True, separators=(",", ":")` | Canonical JSON function |
| Receipt chaining | `previous_receipt_hash` linkage | `verify_chain()` |
| Policy evaluation | Same manifest + same rules → same result | `policy_hash` in `PolicyEvaluation` |
| Blast radius scoring | Same topology → same score | `input_hash` in `BlastRadiusScore` |
| Tenant quota | Same usage → same allow/deny | Deterministic counter comparison |

---

## 8. Deterministic Scheduling Rules

### 8.1 Shard Assignment Algorithm

Workers are assigned to shards via SHA-256 hash:

```
shard_index = int(H(worker_id)[:8], 16) mod shard_count
shard_id = shard_ids[shard_index]
```

**Rule SCHED-1**: For any given `worker_id` and `shard_count`, the assignment is deterministic and reproducible across all executions.

**Rule SCHED-2**: The `assignment_hash` of a `ShardAssignment` is `H("{worker_id}:{shard_id}")`.

### 8.2 Worker Registration

```
register_workers(worker_ids):
  for each worker_id:
    assignment = partitioner.assign(worker_id)
    if |shard_workers[assignment.shard_id]| >= max_workers_per_shard:
      raise ValueError("Shard capacity exceeded")
    shard_workers[assignment.shard_id].add(worker_id)
```

**Rule SCHED-3**: No shard may exceed `max_workers_per_shard`. Default: 32.

**Rule SCHED-4**: Worker registration is idempotent only within a single pipeline run. Re-registering the same worker_id in the same run is an error.

### 8.3 Ephemeral Slot Rules

Workers read and write **ArtifactSlots** on the ArtifactBus:

- `bus.write(slot)` → frozen slot with fingerprint stored
- `bus.read(slot_id)` → immutable reference to stored slot
- `bus.latest_for_family(type, producer)` → most recent slot for family

**Rule SCHED-5**: Workers shall not retain slot references across phase boundaries. Each phase resolves its inputs from the previous phase's boundary receipt.

### 8.4 Centralized Scheduler Guarantees

The `CentralOrchestratorKernel` is the sole scheduling authority:

1. **Fixed phase order**: `PHASE_ORDER` is a constant array
2. **Bounded fanout**: `max_fanout` per phase (default: 8)
3. **Deterministic merge**: Phase status is `SUCCESS` only if all required workers succeed AND no worker fails
4. **No decentralized planning**: Workers do not schedule other workers

**Rule SCHED-6**: The orchestrator shall not permit dynamic phase insertion, reordering, or conditional phase skipping. All phases execute in order, even if empty.

---

## 9. Policy Evaluation Order

### 9.1 Policy Rule Structure

```
PolicyRule:
  rule_id: string
  rule_type: banned_import | max_resource | required_capability | trust_zone_restriction | banned_capability
  condition: {field: string, value: any}
  action: ALLOW | DENY | REQUIRE_REVIEW
  severity: CRITICAL | HIGH | MEDIUM
```

### 9.2 Evaluation Precedence

Rules are evaluated in the order they appear in the policy's `rules` array. Within that order:

1. **CRITICAL** severity rules are evaluated first
2. **HIGH** severity rules are evaluated second
3. **MEDIUM** severity rules are evaluated last

**Rule POLICY-1**: The first rule that produces `DENY` terminates evaluation for that manifest. The final result is `passed=False`.

### 9.3 Fail-Closed Semantics

**Rule POLICY-2**: If a manifest field referenced by a rule condition is missing or `None`, the rule evaluates as `passed=False` (DENY).

**Rule POLICY-3**: If a rule type is unrecognized, the evaluation aborts with `passed=False`.

**Rule POLICY-4**: Empty policy (zero rules) evaluates as `passed=False`. A manifest must have an affirmative policy to be admitted.

### 9.4 Trust-Zone Restriction

Trust zone rules check `manifest.trust_zone.value` against `condition.allowed`:

```
passed = manifest.trust_zone.value in condition.allowed
```

**Rule POLICY-5**: If `allowed` is empty, no trust zone is permitted — all manifests are denied.

### 9.5 Resource Limit Rules

Resource rules compare manifest-declared limits against policy ceilings:

```
passed = manifest.{field} <= condition.max
```

**Rule POLICY-6**: Resource rules use strict `<=`. Equal values are allowed. Exceeding values are denied.

### 9.6 Banned Capability Rules

Banned rules check that dangerous capabilities are disabled:

```
passed = not manifest.{field}  # must be False or missing
```

Banned capabilities include: `network_access`, `filesystem_access`, `subprocess_access`, `dynamic_eval_access`.

---

## 10. Shard Synchronization Semantics

### 10.1 PhaseBarrier Contract

A `PhaseBarrier` represents the synchronization point at the end of a phase:

```
PhaseBoundary:
  phase: string
  shard_id: string  # "global" for cross-shard barriers
  worker_ids: [sorted worker IDs]
  completed: bool
  boundary_hash: H(phase + shard_id + workers + completed)
```

### 10.2 Cross-Shard Coordination

**Rule SHARD-1**: A phase is considered complete only when ALL shards report `ShardState.COMPLETED`.

**Rule SHARD-2**: The orchestrator's `can_advance_phase()` returns `True` if and only if `∀s ∈ shards: shard_states[s] == COMPLETED`.

**Rule SHARD-3**: `advance_phase(next_phase)` computes a global `PhaseBoundary` with `shard_id="global"` and all worker IDs, resets all shard states to `IDLE`, and sets `current_phase = next_phase`.

### 10.3 Failure Isolation

**Rule SHARD-4**: A worker failure in one shard does NOT propagate to other shards' workers within the same phase. However, the phase boundary will be `FAIL`, preventing phase advancement.

**Rule SHARD-5**: Shard state mutations are logged in `execution_log` in deterministic order.

### 10.4 Recovery Rules

**Rule SHARD-6**: If a shard fails, the entire pipeline fails (unless `fail_open=True`). There is no partial commit or compensating transaction.

---

## 11. Receipt Chain Model

### 11.1 ExecutionReceipt Structure

```
ExecutionReceipt:
  receipt_id: UUID
  worker_class: string
  worker_id: string
  phase: string
  input_slot_ids: [sorted strings]
  output_slot_ids: [sorted strings]
  status: PENDING | SUCCESS | FAIL | TIMEOUT | PANIC | SCHEMA_MISMATCH | REPLAY_MISMATCH | RESOURCE_EXCEEDED
  status_detail: string
  determinism_proof: SHA-256
  resource_usage: {cpu_ms: float, memory_mb: float}
  previous_receipt_hash: SHA-256
  receipt_hash: SHA-256
  timestamp: ISO-8601 UTC
```

### 11.2 Receipt Chaining

Receipts form a linear chain within the `OrchestrationLedger`:

```
receipt_0: previous_receipt_hash = ""
receipt_1: previous_receipt_hash = H(receipt_0)
receipt_2: previous_receipt_hash = H(receipt_1)
...
```

**Rule RECEIPT-1**: `OrchestrationLedger.verify_chain()` must return `True` for every closed ledger.

### 11.3 Boundary Receipt Chaining

Phase boundaries form an independent chain:

```
boundary_0: previous_boundary_hash = ""
boundary_1: previous_boundary_hash = H(boundary_0)
...
```

**Rule RECEIPT-2**: Boundary receipts and execution receipts are chained separately but both chains must verify.

### 11.4 Provenance and Audit Trail

The full audit trail of a pipeline execution consists of:

1. `OrchestrationLedger` — all receipts and boundaries
2. `ReplayLedger` — all events emitted during execution
3. `TenantExecutionLog` — per-tenant execution records
4. `AuditLogEntry` (Layer 4) — console-level audit trail

**Rule RECEIPT-3**: Every execution must produce at least one `TenantExecutionRecord` with `pipeline_hash = H(ExplicitCompositionRequest)`.

### 11.5 Replay-Safe Evidence Binding

Evidence is bound to receipts via the `replay_evidence` field in `EventRecord` and the `determinism_proof` field in `ExecutionReceipt`.

**Rule RECEIPT-4**: Evidence hashes must reference artifacts stored in the `SnapshotRegistry` or `ArtifactBus` at the time of execution.

---

## 12. Trust-Zone Promotion Rules

### 12.1 Trust Zone States

| Zone | Authority | Governance |
|------|-----------|------------|
| `CORE_TRUSTED` | Full | Can access all subsystems |
| `GOVERNED_EXTENSION` | Restricted | Subject to policy engine and sandbox |
| `SANDBOX_EXPERIMENTAL` | None | No governance authority; isolated |

### 12.2 Lifecycle State Machine

```
PENDING_INSPECTION
      │
      ▼ inspector passes
STATIC_ANALYZED
      │
      ▼ determinism verified
DETERMINISM_VERIFIED
      │
      ▼ semantic normalized
SEMANTIC_NORMALIZED
      │
      ▼ policy passes
POLICY_APPROVED
      │
      ▼ final admission
    ADMITTED
      │
      ▼ failure at any stage
    REJECTED  ───────────────┐
      │                      │
      ▼ repeated violations  │
   QUARANTINED ◄─────────────┘
```

**Rule TZ-1**: Every extension MUST pass through all stages in order. Skipping stages is forbidden.

### 12.3 Promotion Criteria

**To GOVERNED_EXTENSION**:
- Status must reach `ADMITTED`
- `deterministic_claim == True`
- `replayability_claim == True`
- `trust_zone` must be `GOVERNED_EXTENSION` or `CORE_TRUSTED`
- `policy_evaluation.passed == True`

**To CORE_TRUSTED**:
- `package_hash` must be in `core_trusted_packages` allowlist
- Must already be `GOVERNED_EXTENSION`
- Must have zero policy violations in last N executions

**Rule TZ-2**: `SANDBOX_EXPERIMENTAL` packages can NEVER gain governance authority. `can_gain_governance_authority()` returns `False` for sandbox packages.

### 12.4 Demotion Rules

**Rule TZ-3**: Any extension that produces a `REPLAY_MISMATCH`, `PANIC`, or policy violation during execution is immediately demoted to `QUARANTINED`.

**Rule TZ-4**: Quarantined extensions remain quarantined until manually reviewed and re-admitted through the full lifecycle.

### 12.5 Marketplace Admission

Only extensions with `status == ADMITTED` may appear in the `CapabilityMarketplaceRegistry`.

**Rule TZ-5**: The marketplace registry shall filter out all non-admitted extensions regardless of trust zone.

---

## 13. Reference Implementation Mapping

Every rule in this specification is implemented in the reference codebase as follows.

### 13.1 Artifact Lifecycle

| Rule | File | Function / Class |
|------|------|-----------------|
| ART-1 | `pi-interoperability-layer/contracts.py` | `ArtifactContract.model_config = {"frozen": True}` |
| ART-2 | `pi-interoperability-layer/contracts.py` | `compute_fingerprint()` — `content_hash = H(payload)` |
| ART-3 | `pi-interoperability-layer/contracts.py` | `SchemaEvolutionLog` — append-only records |
| ART-4 | `pi-interoperability-layer/mesh/artifact_bus.py` | `ArtifactSlot.freeze()` and `bus.write()` |
| ART-5 | `pi-interoperability-layer/mesh/artifact_bus.py` | `_slot_versions` dict keyed by `{artifact_type}:{producer_worker_id}` |

### 13.2 Graph Execution

| Rule | File | Function / Class |
|------|------|-----------------|
| GRAPH-1 | `pi-console/backend/src/pi_console/services.py` | `CoreAdapter._validate_dag()` — cycle detection via DFS |
| GRAPH-2 | `pi-console/backend/src/pi_console/services.py` | Node existence validation in `_validate_dag()` |
| GRAPH-3 | `pi-console/backend/src/pi_console/services.py` | Connectivity check in `_validate_dag()` |
| NODE-1 | `pi-interoperability-layer/mesh/kernel.py` | `_run_phase()` — workers execute after input resolution |
| NODE-2 | `pi-interoperability-layer/mesh/kernel.py` | `_merge_phase()` — FAIL blocks dependent phases |
| NODE-3 | `pi-interoperability-layer/mesh/worker_base.py` | `execute()` — bound checks before `_run()` |
| EDGE-1 | `pi-console/backend/src/pi_console/schemas.py` | `CompositionEdge.condition` — string field, no evaluation in core |

### 13.3 Phase Transitions

| Rule | File | Function / Class |
|------|------|-----------------|
| PHASE-1 | `pi-interoperability-layer/mesh/kernel.py` | `run_pipeline()` — sequential phase loop |
| PHASE-2 | `pi-interoperability-layer/mesh/kernel.py` | `_merge_phase()` — status checks |
| PHASE-3 | `pi-interoperability-layer/mesh/kernel.py` | `if merge_status == FAIL and not fail_open` |
| PHASE-4 | `pi-interoperability-layer/mesh/kernel.py` | Empty boundary for unconfigured phases |
| PHASE-5 | `pi-interoperability-layer/mesh/receipts.py` | `PhaseBoundaryReceipt.compute_hash()` |
| PHASE-6 | `pi-interoperability-layer/mesh/kernel.py` | `worker_id = f"{phase}_{cls.__name__}_{i}"` |

### 13.4 Replay Invariants

| Rule | File | Function / Class |
|------|------|-----------------|
| REPLAY-1 | `pi-interoperability-layer/execution.py` | `ReplayLedger.append()` — `seq = last_sequence + 1` |
| REPLAY-2 | `pi-interoperability-layer/execution.py` | `EventRecord.compute_hash()` includes `previous_hash` |
| REPLAY-3 | `pi-interoperability-layer/execution.py` | `ReplayLedger.verify_integrity()` |
| REPLAY-4 | `pi-interoperability-layer/mesh/worker_base.py` | `_compute_determinism_proof()` |

### 13.5 Scheduling

| Rule | File | Function / Class |
|------|------|-----------------|
| SCHED-1 | `pi-interoperability-layer/mesh/shard.py` | `DeterministicPartitioner.assign()` — `int(H(worker_id)[:8], 16) % shard_count` |
| SCHED-2 | `pi-interoperability-layer/mesh/shard.py` | `ShardAssignment.compute_hash()` |
| SCHED-3 | `pi-interoperability-layer/mesh/shard.py` | `ShardCoordinator.register_workers()` — capacity check |
| SCHED-4 | `pi-interoperability-layer/mesh/shard.py` | `register_workers()` raises on duplicate within run |
| SCHED-5 | `pi-interoperability-layer/mesh/kernel.py` | `_resolve_phase_inputs()` — phase-scoped input resolution |
| SCHED-6 | `pi-interoperability-layer/mesh/kernel.py` | `PHASE_ORDER` constant array |

### 13.6 Policy

| Rule | File | Function / Class |
|------|------|-----------------|
| POLICY-1 | `pi-extension-governor/policy.py` | `ExtensionGovernancePolicy.evaluate()` — first DENY wins |
| POLICY-2 | `pi-extension-governor/policy.py` | `_evaluate_rule()` — missing field → passed=False |
| POLICY-3 | `pi-extension-governor/policy.py` | Unrecognized rule type is not in `_build_rules()`, so not evaluated (implicit DENY) |
| POLICY-4 | `pi-extension-governor/policy.py` | `_build_rules()` always returns 10+ rules |
| POLICY-5 | `pi-extension-governor/policy.py` | `trust_zone_restriction` — empty allowed → DENY |
| POLICY-6 | `pi-extension-governor/policy.py` | `max_resource` — `<=` comparison |

### 13.7 Shard Synchronization

| Rule | File | Function / Class |
|------|------|-----------------|
| SHARD-1 | `pi-interoperability-layer/mesh/shard.py` | `can_advance_phase()` — all COMPLETED check |
| SHARD-2 | `pi-interoperability-layer/mesh/shard.py` | Same as above |
| SHARD-3 | `pi-interoperability-layer/mesh/shard.py` | `advance_phase()` — global boundary computation |
| SHARD-4 | `pi-interoperability-layer/mesh/shard.py` | Worker failures don't cross shard boundaries in `_run_phase()` |
| SHARD-5 | `pi-interoperability-layer/mesh/shard.py` | `_execution_log.append(...)` on every state change |
| SHARD-6 | `pi-interoperability-layer/mesh/kernel.py` | `fail_open` gate in `_merge_phase()` |

### 13.8 Receipts

| Rule | File | Function / Class |
|------|------|-----------------|
| RECEIPT-1 | `pi-interoperability-layer/mesh/receipts.py` | `OrchestrationLedger.verify_chain()` |
| RECEIPT-2 | `pi-interoperability-layer/mesh/receipts.py` | Separate chains for receipts and boundaries |
| RECEIPT-3 | `pi-interoperability-layer/platform/tenant.py` | `TenantExecutionLog.record()` |
| RECEIPT-4 | `pi-interoperability-layer/execution.py` | `EventRecord.replay_evidence` field |

### 13.9 Trust Zones

| Rule | File | Function / Class |
|------|------|-----------------|
| TZ-1 | `pi-extension-governor/manifest.py` | `ExtensionStatus` enum ordered sequence |
| TZ-2 | `pi-extension-governor/trust_zones.py` | `can_gain_governance_authority()` |
| TZ-3 | `pi-extension-governor/trust_zones.py` | Demotion logic in `evaluate()` and policy engine |
| TZ-4 | `pi-extension-governor/trust_zones.py` | Quarantine as terminal recovery state |
| TZ-5 | `pi-interoperability-layer/capability/registry.py` | Marketplace registry filters by status |

### 13.10 Layer 4 Boundary

| Rule | File | Function / Class |
|------|------|-----------------|
| INVARIANT-1 | N/A (philosophical) | Enforced by code review: no LLM imports in core |
| INVARIANT-2 | `pi-console/backend/src/pi_console/schemas.py` | `ExplicitCompositionRequest` frozen model |
| INVARIANT-3 | All core files | `frozen=True` on all models; canonical JSON; SHA-256 |
| INVARIANT-4 | `pi-extension-governor/policy.py` | `DENY_OVERRIDES_ALLOW = True` |
| INVARIANT-5 | `pi-interoperability-layer/platform/tenant.py` | `TenantRegistry` — scoped lookups only |

---

## 14. Conformance Test Plan

### 14.1 Test Categories

| Category | Purpose | Count (ref impl) |
|----------|---------|-----------------|
| Boundary Tests | Layer 4 → Layer 1–3 contract enforcement | 17 |
| Artifact Tests | Fingerprinting, serialization, evolution | ~45 |
| Execution Tests | Ledger integrity, event chaining, replay | ~65 |
| Worker Tests | Contract enforcement, determinism proof | ~42 |
| Shard Tests | Deterministic assignment, phase barriers | ~18 |
| Policy Tests | Fail-closed, rule evaluation, trust zones | ~36 |
| Tenant Tests | Quota enforcement, isolation, audit | ~52 |
| Blast Radius Tests | Topology scoring, limit checks | ~11 |
| Diff Tests | Semantic diff computation | ~11 |
| Console Backend Tests | API contract, validation, audit logging | 17 |
| **Total** | | **383** |

### 14.2 Required Conformance Tests

A conformant implementation must pass the following tests:

#### CTEST-1: Artifact Immutability
- Construct an `ArtifactContract` with `frozen=True`
- Attempt field mutation → must raise `ValidationError` or equivalent

#### CTEST-2: Deterministic Fingerprint
- Create two identical artifact instances
- `compute_fingerprint()` must return identical hashes
- Modify one payload field → hash must differ

#### CTEST-3: Ledger Chain Integrity
- Append 5 events to a `ReplayLedger`
- `verify_integrity()` must return `True`
- Tamper with one event's payload → `verify_integrity()` must return `False`

#### CTEST-4: Receipt Chaining
- Append 3 receipts to an `OrchestrationLedger`
- `verify_chain()` must return `True`
- Modify `previous_receipt_hash` of receipt 2 → `verify_chain()` must return `False`

#### CTEST-5: Shard Determinism
- Create a `DeterministicPartitioner(shard_count=4)`
- Assign `worker_id="w1"` 10 times → must always map to the same shard
- Re-create partitioner with same params → same assignment

#### CTEST-6: Phase-Locked Advancement
- Begin phase "EXTRACT" with 2 shards
- Mark 1 shard completed → `can_advance_phase()` must be `False`
- Mark second shard completed → `can_advance_phase()` must be `True`

#### CTEST-7: Policy Fail-Closed
- Evaluate manifest with empty policy rules → `passed=False`
- Evaluate manifest with missing required field → `passed=False`
- Evaluate manifest exceeding resource max → `passed=False`

#### CTEST-8: Tenant Isolation
- Register tenant T1 and T2
- Add capability for T1 → T2's capability count must remain 0
- Query T1 audit log → must not contain T2 entries

#### CTEST-9: ExplicitCompositionRequest Boundary
- Submit plain dict instead of `ExplicitCompositionRequest` → rejected with 422
- Submit request without `user_confirmation=True` → rejected with 403
- Submit request with mismatched tenant header → rejected with 403

#### CTEST-10: Replay Verification
- Execute a pipeline, capture receipts
- Replay same inputs → determinism proofs must match
- Modify one input artifact → determinism proof must differ

#### CTEST-11: Worker Contract Enforcement
- Execute worker with inputs exceeding `max_input_slots` → `RESOURCE_EXCEEDED`
- Execute worker exceeding `max_execution_ms` → `TIMEOUT`
- Execute worker producing output type not in contract → `SCHEMA_MISMATCH`

#### CTEST-12: Blast Radius Boundedness
- Create topology with depth > `max_graph_depth` → limit exceeded in report
- Create topology with fanout > `max_fanout_per_endpoint` → limit exceeded

#### CTEST-13: Trust Zone Sandbox Isolation
- Assign manifest to `SANDBOX_EXPERIMENTAL` → `can_gain_governance_authority()` returns `False`
- Attempt to promote sandbox extension → must fail

#### CTEST-14: Schema Compatibility
- Register contract at version `1.0.0`
- Evaluate candidate `1.1.0` → `compatible=True`
- Evaluate candidate `2.0.0` → `compatible=False`

#### CTEST-15: Console Audit Trail
- Submit composition via console → `AuditLogEntry` created with exact request payload
- Query audit log → must include all fields of submitted request

### 14.3 Test Execution Reference

The reference implementation validates conformance via:

```bash
# Core runtime tests (across all 6 modules)
PYTHONPATH="/path/to/pi-agent-chain/src:/path/to/pi-semantic-diff/src:..." \
  python -m pytest -q

# Console boundary tests
PYTHONPATH=/path/to/pi-console/backend/src \
  python -m pytest tests/backend/test_boundary.py -v
```

All 383 tests must pass. Any failure indicates a spec violation or regression.

---

## 15. Versioning & Maintenance

### 15.1 Specification Versioning

This specification uses **Semantic Versioning**:

- **MAJOR** (X.0.0): Breaking changes to invariants, phase order, or boundary contracts
- **MINOR** (x.Y.0): New artifact types, new capabilities, additive rules
- **PATCH** (x.y.Z): Clarifications, typo fixes, non-normative errata

### 15.2 Change Control Process

1. **Proposal**: Changes proposed via PR with rationale and impact analysis
2. **Review**: Reviewed against all hard invariants (Section 1.4)
3. **Test Update**: All conformance tests updated to reflect changes
4. **Reference Update**: Reference implementation updated and passing
5. **Approval**: Maintainers approve after zero-regression verification
6. **Release**: New spec version published with changelog

### 15.3 Backward Compatibility

- New artifact fields MUST be optional with sensible defaults
- New phases MUST be appended to `PHASE_ORDER`, never inserted
- New policy rule types MUST be additive; existing rules unaffected
- Schema evolution MUST be tracked in `SchemaEvolutionLog`

### 15.4 Deprecation Policy

- Features marked deprecated in version `N` remain functional through `N+1`
- Deprecated features are removed in version `N+2`
- Deprecations are recorded in `SchemaEvolutionLog` with `change_type: DEPRECATE`

---

## 16. Appendices

### Appendix A: Canonical JSON Serialization

All hashes in the PI runtime use this exact serialization:

```python
def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
```

**Rule A-1**: Any deviation from this canonical form (different key order, whitespace, or encoding) produces a different hash and breaks replay.

### Appendix B: SHA-256 Hashing

All hashes use SHA-256:

```python
import hashlib
hashlib.sha256(payload_bytes).hexdigest()
```

`payload_bytes` is the UTF-8 encoding of the canonical JSON string.

### Appendix C: UUID Generation

IDs use standard UUID4 hex truncated to 16 characters:

```python
f"{prefix}_{uuid.uuid4().hex[:16]}"
```

Prefixes: `ecr_`, `sim_`, `rcpt_`, `bnd_`, `ledger_`, `evt_`, `slot_`, `aud_`, `sess_`

### Appendix D: Time Representation

All timestamps are ISO-8601 UTC strings with timezone:

```python
datetime.now(timezone.utc).isoformat()
```

Example: `2026-05-18T14:30:00+00:00`

### Appendix E: Frozen Model Updates

Pydantic v2 frozen models are updated via `model_copy(update=...)`:

```python
# Immutable update pattern
updated = obj.model_copy(update={"field": new_value})
# Original obj remains unchanged
```

**Rule E-1**: Direct field assignment (`obj.field = value`) on frozen models raises `ValidationError`.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-05-18 | Initial specification covering all 4 layers, 15 sections, 14 conformance tests, 54 rules |

---

**End of PI Runtime Specification v1.0**

---

## 17. Snapshot Foundation Layer

### 17.1 Snapshot Artifact Definition

A `SnapshotArtifact` is an immutable, tenant-partitioned, timestamped representation of infrastructure state at a single point in time.

```
SnapshotArtifact:
  snapshot_id: string
  base_snapshot_id: string | null
  timestamp_marker: TimestampMarker
  payload: SnapshotPayload
  payload_hash: SHA-256
  artifact_hash: SHA-256
  previous_snapshot_hash: SHA-256
  compression: "none" | "gzip" | "zstd"
  retention_class: "hot" | "warm" | "cold" | "archive"
```

**Rule SNAP-1**: Every snapshot MUST have a `payload_hash` equal to `H(canonical_json(payload.data))`.

**Rule SNAP-2**: Every snapshot MUST have an `artifact_hash` equal to `H(snapshot_id + base_snapshot_id + timestamp_marker.ordering_key + payload_hash + previous_snapshot_hash)`.

**Rule SNAP-3**: `previous_snapshot_hash` MUST equal the `artifact_hash` of the immediately preceding snapshot in the same (tenant_id, source_id, snapshot_type) chain. The first snapshot in a chain has `previous_snapshot_hash = ""`.

### 17.2 SnapshotRegistry Invariants

**Rule SNAP-4**: The SnapshotRegistry is append-only. No snapshot may be modified, overwritten, or deleted after storage.

**Rule SNAP-5**: Tenant isolation is absolute. A query with `tenant_id=X` MUST only return snapshots where `payload.tenant_id == X`.

**Rule SNAP-6**: Snapshot ordering within a chain is strictly monotonic by `timestamp_marker.ordering_key`.

**Rule SNAP-7**: Clock order violations (a snapshot with `timestamp_marker < chain.head.timestamp_marker`) are rejected with `ClockOrderViolation`.

### 17.3 Retention Policy

```
RetentionPolicy:
  policy_id: string
  hot_ttl_days: int >= 1
  warm_ttl_days: int >= 1
  cold_ttl_days: int >= 1
  archive_ttl_days: int >= 1
  compress_after_days: int >= 1
  compression_algorithm: "gzip" | "zstd"
  immutable_after_days: int >= 1
```

**Rule SNAP-8**: Retention policies only reclassify `retention_class`. They NEVER delete snapshots.

**Rule SNAP-9**: Snapshots older than `immutable_after_days` are sealed: no further writes to their chain are permitted.

---

## 18. Semantic Diff Engine

### 18.1 DeltaType Classification

Every detected change between two snapshots MUST be classified into exactly one `DeltaType`:

| Category | Types |
|----------|-------|
| Structural | NODE_ADDED, NODE_REMOVED, NODE_MODIFIED, EDGE_ADDED, EDGE_REMOVED, EDGE_MODIFIED |
| Configuration | CONFIG_ADDED, CONFIG_REMOVED, CONFIG_CHANGED |
| State | STATE_CHANGED, STATE_INCREASED, STATE_DECREASED |
| Auth/Security | AUTH_ADDED, AUTH_REMOVED, AUTH_CHANGED, PERMISSION_ESCALATED, PERMISSION_DEESCALATED |
| Policy | POLICY_ADDED, POLICY_REMOVED, POLICY_CHANGED |
| Topology | TOPOLOGY_EXPANDED, TOPOLOGY_CONTRACTED, TOPOLOGY_REWIRED |
| Capability | CAPABILITY_ADDED, CAPABILITY_REMOVED, CAPABILITY_UPDATED |
| Trust Zone | TRUST_ZONE_PROMOTED, TRUST_ZONE_DEMOTED |
| Composite | COMPOSITE, UNKNOWN |

**Rule DIFF-1**: Delta classification is deterministic: identical inputs MUST produce identical DeltaType assignments.

**Rule DIFF-2**: Severity is derived from DeltaType via a fixed lookup table, not from probabilistic scoring.

### 18.2 SemanticDriftReport

```
SemanticDriftReport:
  report_id: string
  baseline_snapshot_id: string
  modified_snapshot_id: string
  deltas: [SemanticDelta]
  delta_counts: {delta_type: count}
  high_severity_deltas: [delta_id]
  total_drift_score: float [0, 1]
  structural_drift: float [0, 1]
  semantic_drift: float [0, 1]
  input_hash: SHA-256
  report_hash: SHA-256
```

**Rule DIFF-3**: `total_drift_score` is bounded [0, 1] and computed as `min(total_changes / max(total_elements * 2, 1), 1.0)`.

**Rule DIFF-4**: `report_hash` covers all delta hashes in sorted order, ensuring bit-for-bit reproducibility.

### 18.3 Worker Contract

The `PiObservabilityDiffWorker` implements the `WorkerBase` contract:

- Input: exactly 2 `SnapshotArtifact` slots (baseline, modified)
- Output: 1 `SemanticDriftReport` slot
- Max execution: 60 seconds
- Determinism proof: hash of output slot fingerprint

**Rule DIFF-5**: The worker SHALL reject cross-tenant diffs and cross-type diffs with `SCHEMA_MISMATCH`.

---

## 19. Drift Propagation Simulation

### 19.1 RiskPropagationGraph

A `RiskPropagationGraph` is derived deterministically from a `TopologyGraph` and a `SemanticDriftReport`.

**Rule PROP-1**: Same `TopologyGraph` + same `SemanticDriftReport` MUST always produce the same `RiskPropagationGraph` (verified by `graph_hash`).

### 19.2 Propagation Rules

**Rule PROP-2**: Propagation is bounded by `max_propagation_depth` (default 6). No node beyond depth 6 may receive propagated risk.

**Rule PROP-3**: Auth-carrying edges amplify propagation by `auth_propagation_multiplier` (default 2), reducing effective depth decay.

**Rule PROP-4**: State-carrying edges amplify by `state_propagation_multiplier` (default 1).

**Rule PROP-5**: Risk level decays by depth but never below `INFO`.

**Rule PROP-6**: Direct blast radius nodes (nodes with `in_direct_blast_radius=True`) preserve their original risk level regardless of propagation depth.

### 19.3 Aggregate Metrics

**Rule PROP-7**: `total_nodes_at_risk` is the count of all nodes with `risk_level != "NONE"`.

**Rule PROP-8**: `total_edges_propagating` is the count of edges where `carries_drift=True`.

---

## 20. Temporal Replay Engine

### 20.1 Replay Safety Boundary

The Temporal Replay Engine operates under a strict **no-mutation boundary**:

**Rule REPLAY-A1**: The engine SHALL NOT write to `SnapshotRegistry`, `ArtifactBus`, or any mutable runtime state.

**Rule REPLAY-A2**: The engine SHALL NOT trigger workers, schedules, or orchestration pipelines.

**Rule REPLAY-A3**: The engine SHALL NOT produce `ExecutionReceipt` objects or modify `OrchestrationLedger` entries.

**Rule REPLAY-A4**: All engine outputs (`ReplayCheckpoint`, `ReplayTimeline`) MUST have `read_only=True`.

### 20.2 ReplayCheckpoint

```
ReplayCheckpoint:
  checkpoint_id: string
  tenant_id: string
  source_id: string
  snapshot_type: SnapshotType
  reconstructed_snapshot: SnapshotArtifact
  source_snapshot_ids: [string]
  target_timestamp: ISO-8601
  nearest_snapshot_timestamp: ISO-8601
  checkpoint_hash: SHA-256
  read_only: true
```

**Rule REPLAY-A5**: `reconstructed_snapshot` is the nearest snapshot at or before `target_timestamp`.

**Rule REPLAY-A6**: `checkpoint_hash` covers `source_snapshot_ids` in sorted order, the target timestamp, and `read_only=true`.

### 20.3 State Reconstruction

**Rule REPLAY-A7**: `reconstruct_state_at()` returns `None` if no snapshot exists at or before the target timestamp.

**Rule REPLAY-A8**: `build_timeline()` produces checkpoints in strictly ascending temporal order.

---

## 21. HyperFrames Temporal Rendering

### 21.1 Deterministic Frame Semantics

A `HyperFrame` is a single frame in a temporal rendering sequence with deterministic composition:

**Rule HF-1**: Identical `SemanticDriftReport` + identical `RenderConfig` MUST produce identical `HyperFrameSequence` (verified by `sequence_hash`).

**Rule HF-2**: Frame ordering is deterministic: Frame 0 = baseline, Frames 1..N = delta groups, Frame N+1 = aggregate.

**Rule HF-3**: Frame data is base64-encoded PNG with deterministic matplotlib rendering: fixed DPI, fixed font, fixed color palette, no random layout.

### 21.2 MP4 Encoding

**Rule HF-4**: MP4 encoding uses `libx264` with fixed quality parameter (quality=8) and fixed FPS (default 2).

**Rule HF-5**: Output file hash is deterministic for identical inputs, subject only to codec implementation stability.

### 21.3 RenderConfig

```
RenderConfig:
  config_id: string
  width: int [320, 3840]
  height: int [240, 2160]
  fps: int [1, 60]
  color_palette: {role: hex_color}
  font_family: string
  font_size: int
  layout_seed: string
```

**Rule HF-6**: `layout_seed` is derived from input hash, not a random seed.

---

## 22. Digital Twin Operating Layer Semantics

### 22.1 Definition

The **Governed Semantic Infrastructure Operating Layer** is the integrated system composed of:

1. `SnapshotRegistry` — immutable infrastructure state capture
2. `SemanticDiffEngine` — deterministic drift detection
3. `DriftPropagationEngine` — bounded risk simulation
4. `TemporalReplayEngine` — read-only historical reconstruction
5. `HyperFrameRenderEngine` — deterministic temporal visualization

### 22.2 Integration Pipeline

```
Snapshot A (t0) ─┬─▶ SnapshotRegistry.store(A)
                │
Snapshot B (t1) ─┼─▶ SnapshotRegistry.store(B)
                │
                ├─▶ SemanticDiffEngine.diff(A, B) ─▶ SemanticDriftReport
                │                                      │
                │                                      ▼
                │                              DriftPropagationEngine.simulate(topology, report)
                │                                      │
                │                                      ▼
                │                              RiskPropagationGraph
                │                                      │
                └─────────────────────────────────────┤
                                                        ▼
                                          TemporalReplayEngine.reconstruct_state_at(t0)
                                                        │
                                                        ▼
                                          ReplayCheckpoint (read_only)
                                                        │
                                                        ▼
                                          HyperFrameRenderEngine.render_drift_report(report)
                                                        │
                                                        ▼
                                          HyperFrameSequence ─▶ MP4
```

### 22.3 Governance Invariants

**Rule DT-1**: The Digital Twin layer is **analytical only**. It does not execute, modify, or trigger infrastructure changes.

**Rule DT-2**: All outputs (reports, graphs, checkpoints, frames) are immutable, fingerprinted, and append-only.

**Rule DT-3**: Tenant isolation extends through the entire digital twin pipeline. No cross-tenant snapshot access, diff computation, or risk propagation is permitted.

**Rule DT-4**: The digital twin pipeline is fully replay-safe. Re-running with identical snapshots produces identical reports, identical graphs, and identical frame sequences.

---

## 23. Canonicalization & Clock Rules

### 23.1 Canonical JSON Serialization

All hashing operations use canonical JSON:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
```

**Rule CANON-1**: No whitespace variance. Keys sorted alphabetically. No trailing commas.

### 23.2 Timestamp Normalization

**Rule CLOCK-1**: All timestamps are normalized to UTC with microsecond precision.

**Rule CLOCK-2**: Nanosecond precision is truncated to microseconds deterministically.

**Rule CLOCK-3**: Timestamp comparison uses truncated microsecond values only.

**Rule CLOCK-4**: Clock skew is bounded by `max_skew_seconds` (default 60). Exceeding skew raises `ClockSkewViolation`.

### 23.3 Deterministic Ordering

**Rule CLOCK-5**: `TimestampMarker.ordering_key` format is `ISO:zero_padded_seq:clock_id`, ensuring lexicographic sort equals chronological sort.

**Rule CLOCK-6**: Sequence numbers are monotonically increasing within a single clock domain.

---

## 24. Conformance Test Plan (Digital Twin Extension)

### 24.1 Test Categories

| Category | Minimum Tests | Coverage |
|----------|---------------|----------|
| Snapshot Artifact | 6 | Hash, immutability, chain, retention |
| SnapshotRegistry | 6 | Store, retrieve, list, tenant isolation, integrity |
| DeterministicClock | 4 | Ordering, skew, truncation, canonicalization |
| SemanticDiffEngine | 8 | All delta types, drift scores, report hash |
| PiObservabilityDiffWorker | 4 | Contract, execute, cross-tenant rejection |
| DriftPropagationEngine | 6 | Propagation depth, auth/state edges, aggregates |
| TemporalReplayEngine | 6 | Reconstruct, timeline, no-mutation boundary |
| HyperFrameRenderEngine | 4 | Frame determinism, sequence hash, MP4 encoding |
| Integration | 6 | End-to-end pipeline, determinism proof, tenant isolation |
| **Total** | **50** | |

### 24.2 Test Invariants

**Rule TEST-1**: Every test MUST verify deterministic output: running the same operation twice with identical inputs MUST produce identical hashes.

**Rule TEST-2**: Every mutation-producing component MUST verify that a `ReplayCheckpoint` has `read_only=True`.

**Rule TEST-3**: Cross-tenant tests MUST verify that `ValueError` or `SCHEMA_MISMATCH` is raised for all boundary violations.

---

## 25. Versioning & Maintenance

### 25.1 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-05-18 | Initial baseline: Layers 1–4, artifact lifecycle, scheduling, policy, trust zones |
| 1.1.0 | 2026-05-19 | Digital Twin Extension: Snapshot, Diff, Propagation, Replay, HyperFrames, canonicalization, clock rules |

### 25.2 Compatibility Statement

All v1.0.0 conformance classes remain valid for v1.1.0. v1.1.0 adds new conformance classes:

- **Digital Twin Runtime**: Implements SnapshotRegistry + SemanticDiffEngine + DriftPropagationEngine
- **Replay Runtime**: Implements TemporalReplayEngine with no-mutation boundary
- **Visualization Runtime**: Implements HyperFrameRenderEngine with deterministic encoding

---

*End of PI Runtime Specification v1.1*
