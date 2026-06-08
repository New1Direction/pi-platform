# Pi Semantic Platform — Unified 3-Layer Architecture

## Overview

The semantic capability platform has evolved from a single runtime into a
deterministic capability operating system with three production layers:

```
┌───────────────────────────────────────────────────────────────────┐
│  LAYER 3: CAPABILITY ECONOMY                                 │
│  Marketplace, Composition Engine, Lifecycle Management       │
│  Schema-driven composition requests only                      │
└──────────────────────────────────────────────────────────────────┘
         ↓ explicit schema-validated composition request
┌───────────────────────────────────────────────────────────────────┐
│  LAYER 2: SHARD-COORDINATED DETERMINISTIC EXECUTION FABRIC   │
│  Distributed execution with global phase barriers             │
│  NOT a swarm. Compiler-style scheduler with phase locking.  │
└──────────────────────────────────────────────────────────────────┘
         ↓ deterministic phase-locked execution
┌───────────────────────────────────────────────────────────────────┐
│  LAYER 1: MULTI-TENANT SAAS CONTROL PLANE                   │
│  Tenant isolation, policy enforcement, resource quotas        │
│  Audit logging, compliance reporting, execution history       │
└──────────────────────────────────────────────────────────────────┘
         ↓ tenant-scoped governance
┌───────────────────────────────────────────────────────────────────┐
│  FOUNDATION: SEMANTIC CAPABILITY MESH                        │
│  Registry, Compatibility Graph, Capability Workers           │
│  Catalog Integration, Extension Governor, Replay Ledger       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Multi-Tenant SaaS Control Plane

### Purpose
Isolation, governance, and resource control for multi-tenant deployments.
Every artifact is tenant-scoped. No cross-tenant leakage.

### Components

| Component | File | Role |
|-----------|------|------|
| Tenant | `platform/tenant.py` | Immutable tenant record with deterministic identity |
| TenantRegistry | `platform/tenant.py` | Tenant CRUD + quota enforcement |
| TenantPolicyEngine | `platform/tenant.py` | Per-tenant policy evaluation |
| TenantExecutionLog | `platform/tenant.py` | Append-only execution history |

### Key Invariants
- `tenant_id` is present on every artifact
- Resource quotas are fail-closed (deny if exceeded)
- Audit log is append-only, never mutated
- Execution rate limiting is deterministic per tenant

### API Surface
```python
TenantRegistry.register(tenant)        # provision tenant
TenantRegistry.check_execution_allowed(tenant_id)  # rate gate
TenantPolicyEngine.evaluate_capability_class(tenant_id, cap_class)  # policy gate
TenantExecutionLog.get_compliance_report(tenant_id)  # compliance
```

---

## Layer 2: Shard-Coordinated Deterministic Execution Fabric

### Purpose
Compiler-style distributed execution of capability graphs.
Deterministic partitioning, phase-locked orchestration, ephemeral workers.

### Naming Constraint (CRITICAL)
This layer is formally **NOT** a swarm. The word "swarm" and all
associated semantics (autonomous agents, emergent behavior, decentralized
decision-making, biological analogies) are **prohibited**.

This is a distributed scheduler with global barriers — comparable to
a compiler's intermediate representation scheduler or a database query
execution engine.

### Components

| Component | File | Role |
|-----------|------|------|
| DeterministicExecutionFabric | `platform/execution_fabric.py` | Central coordinator |
| WorkerLease | `platform/execution_fabric.py` | Ephemeral execution lease |
| PhaseBarrier | `platform/execution_fabric.py` | Global synchronization point |
| ExecutionFabricReceipt | `platform/execution_fabric.py` | Full execution record |

### Execution Lifecycle

```
Input: DAG of ExtensionManifests (from Layer 3)
  ↓ assign_to_shard() → deterministic SHA256 partitioning
  ↓ lease_worker() → ephemeral per-phase worker
  ↓ execute_phase() ↓ all shards run in parallel
  ↓ barrier_wait() → ALL shards must complete
  ↓ advance_or_fail() → fail-closed on any failure
  ↓ repeat for next phase
Output: ExecutionFabricReceipt with replay hash
```

### Key Invariants
- SHA256 deterministic shard assignment (same input → same shard, always)
- All shards must pass barrier before phase advance
- Workers are ephemeral — no worker survives across phases
- Failure in any shard aborts entire execution (fail-closed)
- Replay hash is deterministic from inputs alone

---

## Layer 3: Capability Economy / Marketplace

### Purpose
Deterministic package manager for executable capability graphs.
Schema-driven composition. No natural language input. No inference.

### Critical Constraint
This is **NOT** a recommendation system, AI planner, or intent interpreter.
It is a deterministic package manager with explicit composition requests.

### Components

| Component | File | Role |
|-----------|------|------|
| CapabilityMarketplaceRegistry | `platform/marketplace.py` | Listing lifecycle management |
| CompositionEngine | `platform/marketplace.py` | Deterministic graph resolution |
| CompositionRequest | `platform/marketplace.py` | Schema-driven input (JSON only) |
| CompositionResult | `platform/marketplace.py` | Resolved graph or rejection |
| MarketCapabilityListing | `platform/marketplace.py` | Marketplace entry |

### Composition Request Schema (MANDATORY)

```python
class CompositionRequest(BaseModel):
    request_id: str
    tenant_id: str
    description: str                    # human-readable label only
    nodes: List[CompositionNode]        # explicit node definitions
    edges: List[CompositionEdge]        # explicit dependency edges
    max_depth: int = 5                  # bounded recursion
    max_nodes: int = 50                 # bounded graph size
    fail_on_conflict: bool = True        # fail-closed
    deterministic_only: bool = True     # deterministic requirement
```

**NO natural language "intent" field exists.**
**NO inference layer accepts unstructured input.**

### Capability Lifecycle

```
PUBLISHED → UNDER_REVIEW → VERIFIED → ADMITTED → AVAILABLE → [DEPRECATED | REVOKED]
```

### Trust Scoring Model

| Basis | Points | Condition |
|-------|--------|-----------|
| Policy Evidence | 20 | Passed policy gate |
| Determinism Proof | 25 | Verified in sandbox |
| Replay Verification | 25 | Replay-safe confirmed |
| Manual Review | 30 | Human governance approval |

Trust score is evidence-based, NOT probabilistic.

---

## Data Flow Between Layers

### Scenario: Tenant Requests Capability Composition

```
Tenant (Layer 1)
  → checks quota + policy (TenantPolicyEngine)
  ↓ passes → issues tenant-scoped execution permit

CompositionEngine (Layer 3)
  → receives explicit CompositionRequest (JSON schema)
  → validates nodes + edges against catalog
  → resolves dependencies via CapabilityMarketplaceRegistry
  → trust tier enforcement
  → outputs resolved DAG (CompositionResult)

DeterministicExecutionFabric (Layer 2)
  → receives resolved DAG
  → deterministic shard assignment (SHA256)
  → phase-locked execution with global barriers
  → ephemeral worker leasing
  → outputs ExecutionFabricReceipt with replay hash

TenantExecutionLog (Layer 1)
  → records execution result
  → updates compliance report
  → audit trail preserved
```

---

## MVP Build Order (Phased Roadmap)

### Phase 1: Tenant Isolation (COMPLETE)
- Tenant model + registry with deterministic hashing
- Per-tenant resource quotas (fail-closed)
- Per-tenant policy engine
- Execution log + compliance reporting

### Phase 2: Distributed Execution Scaling (COMPLETE)
- Shard coordinator with deterministic partitioning
- Ephemeral worker leasing model
- Phase-locked execution with global barriers
- Replay recovery mechanism

### Phase 3: Capability Marketplace (COMPLETE)
- Marketplace registry with lifecycle states
- Explicit schema-based composition requests
- Deterministic dependency resolution
- Evidence-based trust scoring

### Phase 4: Production Hardening (NEXT)
- Persistence layer (append-only storage)
- API surface (REST/gRPC with schema validation)
- Monitoring + alerting on barrier failures
- Multi-node shard coordinator (currently simulated)

---

## Global Constraints (Non-Negotiable)

Across all 3 layers, these invariants are enforced:

- **No probabilistic reasoning in runtime systems**
- **No LLM inference in execution path**
- **No natural language interpretation layer**
- **No autonomous or emergent behavior**
- **All graph construction must be schema-driven and deterministic**
- **All outputs must be replayable from inputs alone**
- **Validation before mutation**
- **Fail-closed behavior**
- **Evidence-bound claims**
- **Append-only epistemic promotion**

---

## Key Risks + Failure Modes

| Risk | Mitigation |
|------|------------|
| "Intent creep" — pressure to add natural language input | Hard schema enforcement; no NL fields exist in any model |
| "Swarm drift" — teams describing system as autonomous | Strict naming policy; architecture doc explicitly prohibits |
| Non-deterministic shard assignment | SHA256 modulo; tested with 1000 assignments across all shards |
| Worker lease exhaustion | Bounded leases per phase; quota enforcement |
| Trust tier escalation without evidence | All tier transitions require explicit evidence_hash |
| Cross-tenant data leakage | tenant_id on every artifact; registry partitions by tenant |
| Replay hash collision | Full receipt chain + barrier hashes; cryptographically secure |

---

## File Map

```
src/pi_interoperability_layer/platform/
├── __init__.py                    # Exports for all 3 layers
├── tenant.py                      # Layer 1: Multi-tenant control plane
├── execution_fabric.py           # Layer 2: Shard-coordinated execution
└── marketplace.py                 # Layer 3: Capability economy
tests/test_platform_expansion.py    # 42 tests covering all 3 layers
```

---

## Final Note

This is a **deterministic capability operating system**.
It is not an autonomous agent ecosystem.
It does not interpret intent, recommend actions, or exhibit emergent behavior.
It executes explicit, schema-validated, deterministic graphs under
strict governance, with full replayability and auditability.

All expansion reinforces governance — never undermines it.
