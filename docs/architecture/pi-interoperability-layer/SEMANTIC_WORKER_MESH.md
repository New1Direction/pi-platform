# Semantic Worker Mesh Architecture

## Vision

A **governed semantic operating layer for software infrastructure**.

Not a chatbot swarm.  
Not autonomous agents.  
Not probabilistic orchestration.

A deterministic, specialization-first execution substrate where narrow semantic
workers operate under centralized governance with strict contracts, bounded
execution, and replay-safe coordination.

## Core Principle

Semantic cognition assists infrastructure — it does not replace infrastructure.

## Architectural Tenets

1. **Centralized Governance** — single authoritative scheduler, no decentralized planning
2. **Deterministic Orchestration** — fixed execution phases, deterministic routing
3. **Specialization over Generalization** — narrow workers with fixed responsibilities
4. **Bounded Semantics** — every worker has strict execution bounds
5. **Replay-Governed Authority** — all execution is replay-verifiable
6. **Evidence-Bound Claims** — every output is provenance-linked
7. **Fail-Closed** — default deny on all boundaries
8. **Non-Self-Modifying** — workers cannot mutate their own contracts
9. **Zero Recursive Spawning** — no worker can spawn another worker autonomously

## System Resemblance

- Distributed compiler pipeline (preprocessor → lexer → parser → typechecker → optimizer → codegen)
- Operating system kernel (scheduler → process table → system calls → I/O dispatch)
- Deterministic dataflow engine (fixed DAG, bounded queues, deterministic merge)

## What This Is NOT

- NOT an agent swarm with emergent behavior
- NOT a recursive planning system
- NOT a probabilistic workflow engine
- NOT a self-improving orchestrator
- NOT a chatbot pipeline

## Execution Model

```
Central Orchestration Kernel
    ├── Phase 1: INGEST      → snapshot workers, schema workers
    ├── Phase 2: EXTRACT     → extraction workers, topology workers
    ├── Phase 3: DIFF        → diff workers, auth workers, replay workers
    ├── Phase 4: VALIDATE    → validation workers, policy workers
    ├── Phase 5: RISK        → topology workers, blast radius workers
    ├── Phase 6: GOVERN      → registry workers, lineage workers
    ├── Phase 7: EMIT        → visualization workers, CI/CD gate workers
```

Phases are **fixed order**. Within a phase, workers execute in **bounded parallel
fanout** with deterministic merge points. No phase begins until the previous phase
reaches a deterministic quorum.

## Worker Contract Structure

Every worker MUST define:

| Field | Description |
|-------|-------------|
| `worker_class` | Taxonomy class (e.g. EXTRACTION_WORKER) |
| `input_contract` | Immutable input schema with version |
| `output_contract` | Immutable output schema with version |
| `execution_bounds` | CPU time, memory, artifact count, traversal depth |
| `replay_semantics` | Deterministic replay identity hash requirements |
| `provenance_requirements` | Required upstream provenance chain entries |
| `failure_conditions` | Exact conditions causing FAIL vs BLOCKED vs TIMEOUT |
| `resource_ceilings` | Max file descriptors, max network calls, max subprocesses |
| `determinism_proof` | Schema of evidence that output is deterministic |

## Worker Taxonomy

### Ingest Workers
| Worker | Responsibility |
|--------|---------------|
| `SnapshotIngestWorker` | Load source snapshots into canonical artifact format |
| `SchemaValidationWorker` | Validate incoming artifacts against registered schemas |
| `ProvenanceVerificationWorker` | Verify upstream provenance chain integrity |

### Extract Workers
| Worker | Responsibility |
|--------|---------------|
| `EndpointExtractionWorker` | Extract endpoint signatures from source code |
| `DependencyExtractionWorker` | Extract static dependency edges |
| `AuthExtractionWorker` | Extract auth invariants and rotation classes |
| `MutationExtractionWorker` | Extract mutation class assignments per endpoint |

### Diff Workers
| Worker | Responsibility |
|--------|---------------|
| `EndpointDiffWorker` | Compute endpoint-level behavioral deltas |
| `DependencyDiffWorker` | Compute dependency graph evolution |
| `AuthDiffWorker` | Compute auth invariant drift |
| `ReplaySurfaceDiffWorker` | Compute replay class degradation |

### Validate Workers
| Worker | Responsibility |
|--------|---------------|
| `BoundaryValidationWorker` | Forbidden trust boundary crossing detection |
| `LayerValidationWorker` | Runtime layering violation detection |
| `MutationDriftWorker` | Mutation class escalation detection |
| `ReplaySafetyWorker` | Production replay prohibition enforcement |
| `PolicyComplianceWorker` | Architecture policy rule enforcement |

### Topology Workers
| Worker | Responsibility |
|--------|---------------|
| `TopologyBuildWorker` | Assemble dependency topology from extracted edges |
| `TopologyDiffWorker` | Compute topology structure deltas |
| `ComplexityScoringWorker` | Compute bounded complexity metrics |

### Blast Radius Workers
| Worker | Responsibility |
|--------|---------------|
| `PropagationRiskWorker` | Dependency expansion limit detection |
| `TopologyExpansionWorker` | Node/edge/fanout/depth growth detection |
| `AuthBoundaryWideningWorker` | Auth surface expansion detection |
| `ReplayHazardWorker` | Replay propagation scope detection |
| `MutationImpactWorker` | Downstream mutation impact scoring |

### Registry Workers
| Worker | Responsibility |
|--------|---------------|
| `SnapshotRegistryWorker` | Immutable snapshot storage with retention |
| `BundleRegistryWorker` | Replay bundle assembly and retrieval |
| `LineageRegistryWorker` | Ancestor chain tracking, cycle detection |
| `SchemaRegistryWorker` | Schema version authority, compatibility gate |

### Policy Workers
| Worker | Responsibility |
|--------|---------------|
| `PolicyCompilationWorker` | Compile architecture-policy.json into execution rules |
| `PolicyInheritanceWorker` | Apply environment overlays and inheritance chains |
| `PolicyDriftWorker` | Detect policy rule changes between versions |

### Replay Workers
| Worker | Responsibility |
|--------|---------------|
| `ReplayLedgerWorker` | Append-only event log with chain hashing |
| `ReplayVerificationWorker` | Verify execution matches deterministic replay hash |
| `ReplayCoordinationWorker` | Distributed replay synchronization without consensus |

### Lineage/Provenance Workers
| Worker | Responsibility |
|--------|---------------|
| `ProvenanceAssemblyWorker` | Build provenance chains from execution receipts |
| `LineageQueryWorker` | Serve deterministic lineage traversal queries |
| `EvidenceBindingWorker` | Bind evidence artifacts to violation claims |

### Visualization Workers
| Worker | Responsibility |
|--------|---------------|
| `ValidationReportRenderer` | Render validation output as HTML/JSON |
| `DiffHeatmapRenderer` | Render semantic drift heatmaps |
| `TopologyGraphRenderer` | Render topology as graph structures |
| `GovernanceDashboardRenderer` | Render unified governance dashboard |

### CI/CD Gate Workers
| Worker | Responsibility |
|--------|---------------|
| `MergeGateWorker` | Deterministic merge gate evaluation (PASS/FAIL) |
| `ArtifactVerificationWorker` | Verify artifact integrity before CI promotion |
| `PreDeployGateWorker` | Pre-deployment governance gate |

## Event-Sourced Coordination

### Append-Only Event Log
- Every worker execution produces an `ExecutionReceipt`
- Receipts are appended to a per-pipeline `OrchestrationLedger`
- Ledger has chain hashing: `receipt_hash = H(prev_hash + receipt_payload)`
- Ledger is closed at phase boundaries with a `PhaseBoundaryReceipt`

### Deterministic Artifact Bus
- Workers read inputs from immutable artifact slots
- Workers write outputs to immutable artifact slots
- Slots are versioned and fingerprinted
- No in-place mutation: every write creates a new slot version

### Replayable Orchestration Timeline
- Entire pipeline execution can be replayed from the ledger
- Replay requires: initial snapshots + orchestration ledger + worker binaries
- Replay produces identical outputs or fails closed

## Parallelism Model

### Within a Phase
```
Phase N: EXTRACT
    ├── fanout: [EndpointExtractionWorker, DependencyExtractionWorker, AuthExtractionWorker]
    ├── bounded: max 8 concurrent workers
    ├── deterministic merge: ordered by worker registration order
    └── merge produces: UnifiedExtractionArtifact
```

### Phase Boundaries
- Phase N+1 begins only after Phase N merge completes
- Merge is deterministic: ordered by worker ID, not completion time
- No async phase transitions: all-or-nothing per phase

### No Decentralized Quorum
- Central orchestrator decides when a phase is complete
- No worker votes, no consensus, no probabilistic completion
- Completion is: all registered workers produced receipts + merge succeeded

## Failure Model

| Condition | Behavior |
|-----------|----------|
| Worker TIMEOUT | Receipt marked TIMEOUT, phase blocked unless fail_open=false |
| Worker FAIL | Receipt marked FAIL, phase propagates FAIL to next phase |
| Worker PANIC | Receipt marked PANIC, entire pipeline stopped, ledger closed |
| Schema mismatch | Receipt marked SCHEMA_MISMATCH, phase blocked |
| Replay hash mismatch | Receipt marked REPLAY_MISMATCH, phase blocked |
| Resource ceiling hit | Receipt marked RESOURCE_EXCEEDED, phase blocked |
| Central orchestrator fault | All workers enter FAIL_CLOSED, no continued execution |

## Scaling Characteristics

| Dimension | Strategy |
|-----------|----------|
| Horizontal workers | Add more narrow workers of same taxonomy class |
| Vertical workers | Increase execution bounds within taxonomy limits |
| Pipeline throughput | Parallel phase execution across independent pipelines |
| Artifact volume | Scale snapshot registry storage, not worker count |
| Query load | Scale read-only query workers, not execution workers |

## CI/CD Integration

```yaml
pi-semantic-mesh:
  - phase: INGEST
    workers: [snapshot_ingest, schema_validate, provenance_verify]
  - phase: EXTRACT
    workers: [endpoint_extract, dependency_extract, auth_extract]
  - phase: DIFF
    workers: [endpoint_diff, dependency_diff, auth_diff, replay_diff]
  - phase: VALIDATE
    workers: [boundary_validate, layer_validate, mutation_drift, replay_safety, policy_compliance]
  - phase: RISK
    workers: [propagation_risk, topology_expansion, auth_boundary, replay_hazard, mutation_impact]
  - phase: GOVERN
    workers: [snapshot_registry, bundle_registry, lineage_registry]
  - phase: EMIT
    workers: [merge_gate, artifact_verify, dashboard_render]
```

## Anti-Patterns (Explicitly Forbidden)

1. **Recursive worker spawning** — workers MAY NOT invoke the orchestrator
2. **Dynamic phase insertion** — phases are fixed at compile time
3. **Probabilistic routing** — routing tables are deterministic lookup tables
4. **Self-modifying contracts** — worker contracts are frozen at registration
5. **Emergent plan formation** — no agent planning, no LLM-driven orchestration
6. **Degraded continuation** — partial success is failure
7. **Speculative execution** — no branch prediction, no lookahead workers
8. **Autonomous checkpointing** — checkpoints are orchestrator-managed only

## Next Implementation Priorities

1. **CentralOrchestratorKernel** — scheduler, phase controller, merge coordinator
2. **WorkerBase** — abstract base class enforcing contract validation
3. **ExecutionReceipt** — immutable receipt with chain hashing
4. **OrchestrationLedger** — append-only ledger with phase boundaries
5. **ArtifactBus** — immutable slot-based artifact exchange
6. **First 10 specialized workers** with deterministic implementations
7. **Test harness** — deterministic replay verification for all workers
