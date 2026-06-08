# pi-semantic-recon — Async/Distributed Execution Plan

> **Version:** 1.0
> **Date:** 2026-05-18
> **Scope:** Migrate from single-threaded sequential pipeline to bounded async distributed execution
> **Constraint:** Governance guarantees are preserved. Workers are replaceable pure functions. No autonomous orchestration.

---

## EXECUTIVE SUMMARY

The current runtime executes sequentially: acquire → parse → extract → type → map → synthesize → verify (×6 phases). At scale, this creates the ten bottlenecks documented in `PRODUCTION_SCALE_ANALYSIS.md`.

This plan describes a migration to **bounded asynchronous distributed execution** without weakening any governance guarantee. The core principle remains:

> **Semantic cognition assists infrastructure. Infrastructure remains authoritative.**

**Target end state:**
- Distributed semantic extraction infrastructure
- Replay-governed protocol analysis fabric
- Deterministic topology governance system

**NOT target:**
- Autonomous AI swarm
- Self-evolving agent mesh
- Probabilistic orchestration runtime

---

## 1. CENTRALIZED GOVERNANCE KERNEL

### Principle
The `GovernanceKernel` remains the sole authority for:
- Transition legality
- Replay authority
- Artifact promotion
- Provenance integrity
- Entropy thresholds
- Epistemic promotion

**Workers NEVER:**
- Self-route
- Self-spawn
- Self-modify
- Mutate policies
- Bypass replay gates
- Make governance decisions

### Kernel Architecture

```
┌─────────────────────────────────────────────┐
│         GOVERNANCE KERNEL (single)          │
│  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Policy     │  │  Promotion Logic    │  │
│  │  Registry   │  │  (monotonic rules)  │  │
│  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Entropy    │  │  Artifact Registry  │  │
│  │  Monitor    │  │  (event-sourced)    │  │
│  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────┘
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
┌─────────┐  ┌──────────┐  ┌──────────┐
│ Worker 1│  │ Worker 2 │  │ Worker N │
│ (pure)  │  │ (pure)   │  │ (pure)   │
└─────────┘  └──────────┘  └──────────┘
```

### Kernel Responsibilities

| Function | Ownership | Worker Access |
|---|---|---|
| Epistemic promotion | Kernel only | Read-only (workers query state) |
| Transition legality | Kernel only | Workers request, kernel approves |
| Replay scheduling | Kernel only | Workers receive replay assignments |
| Entropy threshold enforcement | Kernel only | Workers report metrics |
| Artifact registry | Kernel owns event log | Workers append events, never modify |
| Policy mutation | Kernel only | Workers are policy-agnostic |
| HALT decisions | Kernel only | Workers stop on HALT signal |

### Communication Model
- **Worker → Kernel:** Report-only (results, metrics, violations). No request for exception.
- **Kernel → Worker:** Assignments (packets to process, replay tasks, shard boundaries). Commands are idempotent.
- **Async, bounded queues:** Workers pull from bounded assignment queues. Backpressure propagates to acquisition.

---

## 2. ASYNC WORKER EXECUTION MODEL

### Worker Taxonomy

Six bounded worker types. Each is a replaceable pure function.

#### 2.1 Acquisition Workers

**Function:** Ingest raw traffic, normalize payloads, produce `NormalizedTrafficPacket`s.

**Constraints:**
- Stateless: no memory of prior packets
- Bounded queue: max 1000 pending packets per worker
- Lease-based: each packet assigned with `acquisition_lease_expiry`. Expired packets reassigned deterministically.
- Compression/format detection only — no semantic extraction

**Overflow behavior:**
- Queue full → backpressure to traffic source (drop or buffer externally)
- Lease expiry → deterministic reassignment (`packet_id % num_workers`)
- Format unsupported → emit `UNSUPPORTED_PAYLOAD` event to kernel, packet tagged `OBSERVED` with error

#### 2.2 Normalization Workers

**Function:** Run `PayloadNormalizer` on raw packets. Produce decompressed, format-tagged payloads.

**Constraints:**
- Stateless transformation: `raw_bytes → PayloadNormalization`
- Deterministic: same input always produces same output
- Byte-exact envelope preservation: `raw_bytes` never mutated

**Overflow behavior:**
- Decompression failure → `DECOMPRESSION_FAILED` event, packet continues with raw bytes
- Malformed payload → `PARSING_FAILED` event, packet tagged with `decoding_errors`
- Unsupported format → `UNSUPPORTED_FORMAT` event, packet proceeds as binary

#### 2.3 Replay Workers

**Function:** Execute replay requests against observed endpoints. Produce `ReplayValidationResult`s.

**Constraints:**
- **Single replay authority:** One replay coordinator (can have multiple executors, but coordinator serializes assignments)
- Identity-hash grouping: identical packets replayed once, result propagated
- Bounded concurrency: max 10 concurrent replays
- Timeout: deterministic (e.g., 30s), never adaptive
- Mutation-aware: uses mutation-class taxonomy for classification

**Overflow behavior:**
- Rate-limited by endpoint → `REPLAY_DEFERRED` state, rescheduled at deterministic interval
- Endpoint unavailable → `REPLAY_FAILED` with `ENDPOINT_UNAVAILABLE`, not speculative classification
- Auth token expiry → `REPLAY_FAILED` with `AUTH_EXPIRED`, triggers re-auth (external to worker)

#### 2.4 Quorum Workers

**Function:** Execute `SemanticQuorum` over artifact sets. Produce `SemanticQuorumReport`s.

**Constraints:**
- Property-path sharding: each worker handles a deterministic shard of property paths
- Claim deduplication before intersection
- Bounded conflict set size (from `ValidationBoundsConfig`)
- Independent per shard: no cross-worker quorum communication

**Overflow behavior:**
- Conflict set exceeds `max_entropy_semantic_conflicts` → truncate with `CONFLICT_SET_OVERFLOW`
- Claims exceed `max_quorum_claims` → truncate with `CLAIM_OVERFLOW`, emit violation
- Intersections exceed `max_quorum_intersections` → halt shard with `INTERSECTION_OVERFLOW`

#### 2.5 FSM Workers

**Function:** Build and validate `ProtocolStateMachine`s per endpoint.

**Constraints:**
- One FSM per endpoint: no global FSM
- State abstraction: deterministic rules (status code ranges → super-states)
- Bounded size: `max_fsm_nodes`, `max_fsm_edges`, `max_fsm_fanout`, `max_fsm_depth`
- Cycle detection on every update

**Overflow behavior:**
- Nodes exceed `max_fsm_nodes` → `NODE_OVERFLOW` violation, FSM truncated
- Edges exceed `max_fsm_edges` → `EDGE_OVERFLOW` violation, new edges rejected
- Cycle detected → `CYCLE_DETECTED` violation, offending transition rejected

#### 2.6 Entropy Workers

**Function:** Compute entropy metrics across snapshots, structural nodes, semantic conflicts, auth bindings, FSM nodes.

**Constraints:**
- Incremental computation: delta between snapshots, not full re-computation
- Hierarchical: endpoint-level first, detail-level only on change
- Snapshot decimation: deterministic power-of-2 interval retention
- Bounded window: `max_entropy_window_size`

**Overflow behavior:**
- Window exceeds `max_entropy_window_size` → drop oldest snapshot (FIFO)
- Structural nodes exceed `max_entropy_structural_nodes` → cap at bound, emit `STRUCTURAL_OVERFLOW`
- Semantic conflicts exceed `max_entropy_semantic_conflicts` → cap at bound, emit `CONFLICT_OVERFLOW`
- Monotonicity violation → report to kernel, kernel decides HALT

---

### Worker Pool Sizing

| Worker Type | Min | Max | Scaling Trigger | Scaling Action |
|---|---|---|---|---|
| Acquisition | 2 | 16 | Queue depth > 80% | Add worker deterministically (round-robin) |
| Normalization | 2 | 8 | Queue depth > 80% | Add worker deterministically |
| Replay | 1 coordinator + 2 executors | 1 coordinator + 10 executors | Deferred replays > 100 | Add executor deterministically |
| Quorum | 2 | 16 | Shard latency > 5s | Add worker for new shard split |
| FSM | 2 | 8 | Endpoint count > 50/worker | Rehash endpoints deterministically |
| Entropy | 2 | 8 | Snapshot backlog > 32 | Add worker deterministically |

**Critical constraint:** Pool max is hardcoded. NEVER auto-scale beyond max. Workers are replaceable; exceeding max means human operator intervention or configuration change.

---

## 3. DISTRIBUTED SHARDING MODEL

### Sharding Dimensions

Three independent sharding axes. A worker is assigned a deterministic `(trace_shard, endpoint_shard, property_shard)` tuple.

#### 3.1 Trace Partitioning

**Key:** `execution_id` (or hash of trace identifier)
**Purpose:** All packets in a single execution trace stay together for provenance integrity.
**Assignment:** `worker_index = hash(execution_id) % num_acquisition_workers`

**Invariant:** Packets from the same trace never split across workers. Prevents cross-worker provenance races.

#### 3.2 Endpoint Partitioning

**Key:** `endpoint_template` (e.g., `/api/v1/users/{id}`)
**Purpose:** FSM and replay state is endpoint-local.
**Assignment:** `worker_index = hash(endpoint_template) % num_fsm_workers`

**Invariant:** Same endpoint always routes to same FSM worker. FSM state is sticky per endpoint.

#### 3.3 Replay Partitioning

**Key:** `packet_identity_hash` (method + normalized path + normalized payload hash)
**Purpose:** Identical packets replay once, result shared.
**Assignment:** Deterministic grouping before replay. Coordinator owns grouping table.

**Invariant:** Identical packets always get the same replay result. No redundant replays.

### Prohibited Patterns

| Pattern | Status | Reason |
|---|---|---|
| Quorum-of-quorums | **PROHIBITED** | Violates deterministic intersection semantics |
| Recursive worker spawning | **PROHIBITED** | Violates bounded execution guarantee |
| Dynamic shard splits mid-execution | **PROHIBITED** | Causes non-deterministic routing |
| Cross-shard FSM merges | **PROHIBITED** | FSMs are endpoint-local |
| Cross-shard replay sharing without coordinator | **PROHIBITED** | Violates replay authority centrality |

---

## 4. REPLAY SEMANTICS IN DISTRIBUTED MODE

### Principle
Replay remains the highest authority. Distributed execution must not weaken replay determinism.

### Requirements

#### 4.1 Deterministic Replay
- Same packet + same endpoint state → same result
- Replay assignments are deterministic (coordinator serializes)
- Replay results are broadcast to all shards via event log

#### 4.2 Mutation-Aware Classification
- Mutation class is computed BEFORE replay
- Replay result is interpreted through mutation class lens
- Auth drift is independent dimension

#### 4.3 Provenance Chains
- Every replay result is an artifact in the event log
- Ancestry: `original_packet_artifact → replay_assignment_artifact → replay_result_artifact`
- All three are globally ordered in the event log

#### 4.4 Exact Replay Lineage
- Replay lineage is traceable through artifact registry
- `ReplayValidationResult` contains `replay_artifact_id` for audit
- Replays are reproducible: re-executing the same assignment produces the same result (assuming endpoint state is frozen)

### Replay Coordinator Design

```
┌────────────────────────────────────┐
│      REPLAY COORDINATOR            │
│  ┌──────────────────────────────┐  │
│  │  Assignment Queue            │  │
│  │  (bounded, FIFO)             │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Identity Hash Table         │  │
│  │  (packet_hash → result_ref)  │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Broadcast Outbox            │  │
│  │  (to all workers)            │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
         │           │
         ▼           ▼
┌─────────────┐ ┌─────────────┐
│ Executor 1  │ │ Executor 2  │
│ (max 10)    │ │ (max 10)    │
└─────────────┘ └─────────────┘
```

**Coordinator rules:**
1. Receive replay request from any worker
2. Check identity hash table. If exists, return cached result.
3. If not, assign to least-loaded executor.
4. Executor sends request, receives response.
5. Coordinator stores result in identity hash table.
6. Coordinator broadcasts result to requesting worker(s).
7. All assignments and results append to event log.

---

## 5. FAILURE MODEL

### Principle
The system remains **fail-closed**. Distributed execution must not introduce degraded continuation, partial truth, or speculative behavior.

### Failure Scenarios and Responses

#### 5.1 Worker Crash

**Detection:** Heartbeat timeout (e.g., 30s no response)
**Response:**
1. Kernel marks worker as `FAILED`
2. Kernel reassigns in-flight assignments deterministically
3. Kernel emits `WORKER_CRASH` violation
4. Replay coordinator invalidates identity hash entries from crashed worker (they will be recomputed)
5. Quorum shards from crashed worker are reassigned

**What is NOT done:**
- NO speculative continuation of partial results
- NO assumption that crashed worker's results were valid
- NO autonomous spawn of replacement worker

#### 5.2 Network Partition

**Detection:** Worker reachable but kernel unreachable (or vice versa)
**Response:**
1. Partitioned worker stops processing new assignments (fail-closed)
2. Worker completes in-flight tasks if kernel timeout permits
3. If partition persists > lease expiry, kernel reassigns all worker's leases
4. Post-recovery: worker re-syncs from event log, discards any uncommitted local state

**What is NOT done:**
- NO split-brain artifact creation
- NO probabilistic merge of divergent worker states
- NO "last writer wins" without deterministic rule

#### 5.3 Kernel Crash

**Detection:** Workers detect kernel heartbeat timeout
**Response:**
1. All workers enter `GOVERNANCE_SUSPENDED` state
2. Workers complete in-flight pure transformations (no promotion, no replay)
3. Workers buffer results locally (bounded)
4. New kernel instance recovers from event log
5. Workers replay buffered results to new kernel

**What is NOT done:**
- NO worker assumes governance authority
- NO autonomous promotion during kernel outage
- NO probabilistic recovery from partial log

#### 5.4 Replay Endpoint Failure

**Detection:** Executor timeout or 5xx response
**Response:**
1. Result tagged `REPLAY_FAILED` with `ENDPOINT_UNAVAILABLE`
2. Packet epistemic state stays at `OBSERVED` or `INFERRED` (never promoted to `VERIFIED`)
3. Coordinator schedules retry at deterministic interval (e.g., 60s)
4. Max retries: configurable (default 3). After max retries, `REPLAY_FAILED` becomes permanent.

**What is NOT done:**
- NO speculative classification of unreplayed packet
- NO adaptive timeout tuning
- NO "probably equivalent" fallback

#### 5.5 Entropy Threshold Breach

**Detection:** Entropy worker reports monotonicity violation or threshold exceedance
**Response:**
1. Entropy worker reports to kernel
2. Kernel evaluates whether breach is local (single trace) or global
3. Local breach: HALT the trace, other traces continue
4. Global breach: HALT entire pipeline, emit `GLOBAL_ENTROPY_VIOLATION`

**What is NOT done:**
- NO probabilistic continuation with "reduced confidence"
- NO degradation to partial truth
- NO autonomous adjustment of thresholds

---

## 6. EVENT-SOURCED ARTIFACT LOG

### Principle
All state changes are events. The log is the source of truth. Workers reconstruct local state by replaying events.

### Event Types

| Event | Producer | Consumers | Determinism |
|---|---|---|---|
| `PACKET_ACQUIRED` | Acquisition worker | Normalization workers | Hash-based routing |
| `PACKET_NORMALIZED` | Normalization worker | Extraction workers | Trace-shard sticky |
| `EXTRACTION_COMPLETE` | Extraction worker | FSM, Quorum workers | Endpoint-shard sticky |
| `FSM_UPDATED` | FSM worker | Entropy worker | Endpoint-shard sticky |
| `REPLAY_ASSIGNED` | Replay coordinator | Replay executors | Coordinator serializes |
| `REPLAY_COMPLETE` | Replay executor | All workers | Broadcast |
| `QUORUM_SHARD_COMPLETE` | Quorum worker | Kernel | Shard aggregation |
| `ENTROPY_SNAPSHOT` | Entropy worker | Kernel | Stream |
| `ARTIFACT_PROMOTED` | Kernel | All workers | Centralized |
| `GOVERNANCE_HALT` | Kernel | All workers | Centralized |

### Log Properties

- **Append-only:** Events are never deleted or modified
- **Totally ordered:** All workers see events in the same order
- **Deterministic replay:** Replaying events 1..N reproduces exact state at N
- **Bounded retention:** Hot log (last hour) in memory. Warm log (last 24h) on disk. Cold log in object storage.
- **Validation:** Each event carries hash of previous event. Chain integrity verifiable.

### Implementation Options

| Option | Pros | Cons |
|---|---|---|
| **NATS JetStream** | Lightweight, exactly-once delivery, native Go | Single-node throughput limit |
| **Apache Kafka** | Battle-tested, massive throughput, partitioning | Heavy operational overhead |
| **Raft (etcd/bbolt)** | Strong consistency, embedded, no external deps | Leader bottleneck, complex failover |
| **SQLite WAL + fsync** | Simplest, zero external dependencies | Single-writer limit |

**Recommendation:** Start with NATS JetStream (embedded). Migrate to Kafka only if throughput exceeds JetStream limits (theoretical: ~1M events/sec, practical: ~100K events/sec).

---

## 7. TARGET END STATE

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      TRAFFIC SOURCES                            │
│  (pcap, proxy, API gateway, synthetic generator)                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              ACQUISITION WORKER POOL (2-16)                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐        ┌─────────┐       │
│  │ Worker  │ │ Worker  │ │ Worker  │  ...   │ Worker  │       │
│  │   1     │ │   2     │ │   3     │        │   N     │       │
│  └─────────┘ └─────────┘ └─────────┘        └─────────┘       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│           NORMALIZATION WORKER POOL (2-8)                       │
│  Decompression, format detection, parsing, error tagging        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│         EXTRACTION WORKER POOL (2-8, node 2-5)                  │
│  Structural extraction, semantic typing, flow mapping           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              GOVERNANCE KERNEL (single)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │  Event Log  │  │  Artifact   │  │  Promotion Logic    │     │
│  │  (append)   │  │  Registry   │  │  (monotonic rules)  │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ REPLAY COORDINATOR│ │  FSM WORKER     │ │  QUORUM WORKER  │
│ (1 + 2-10 exec)  │ │  POOL (2-8)     │ │  POOL (2-16)    │
│ Identity-hash    │ │  Per-endpoint   │ │  Per-property   │
│ grouping         │ │  FSM state      │ │  path shard     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
              │               │               │
              └───────────────┼───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│         ENTROPY WORKER POOL (2-8)                               │
│  Incremental computation, hierarchical analysis, drift detection│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              OUTPUT: SYNTHESIZED SPEC                           │
│  OpenAPI 3.1, protobuf schema, or custom protocol spec          │
└─────────────────────────────────────────────────────────────────┘
```

### What This Is
- Distributed semantic extraction infrastructure
- Replay-governed protocol analysis fabric
- Deterministic topology governance system

### What This Is NOT
- Autonomous AI swarm
- Self-evolving agent mesh
- Probabilistic orchestration runtime
- Self-modifying execution graph
- Recursive quorum-of-quorums

---

## 8. MIGRATION PHASES

### Phase 1: Event Log Foundation (Week 1-2)
- Implement event-sourced artifact log
- Convert `ArtifactRegistry` to append-only event log
- All artifact operations emit events
- No workers yet — still single-threaded

### Phase 2: Worker Pool Extraction (Week 3-4)
- Extract acquisition → normalization → extraction into sequential worker pools
- Pools are fixed-size, assign work via bounded queues
- Kernel still single-threaded, but workers run in threads
- Validation remains sequential for now

### Phase 3: Phase-Parallel Validation (Week 5-6)
- Split verification into parallel phases where independent
- Provenance + Replay + Auth in parallel
- State Transition depends on Auth output
- Quorum depends on all prior
- Entropy depends on all prior

### Phase 4: Distributed Sharding (Week 7-8)
- Implement trace partitioning, endpoint partitioning
- Multiple worker machines (if needed)
- Event log becomes distributed (NATS JetStream)
- Kernel remains single instance

### Phase 5: Replay Coordination (Week 9-10)
- Implement centralized replay coordinator
- Identity-hash grouping
- Deterministic broadcast
- Quorum shards consume replay results

### Phase 6: Entropy Hardening (Week 11-12)
- Incremental entropy computation
- Snapshot decimation
- Hierarchical endpoint-level analysis
- Drift detection with bounded false-positive rate

---

## 9. INVARIANT CHECKLIST

After migration, verify:

- [ ] Workers are replaceable pure functions
- [ ] Workers never self-route, self-spawn, or self-modify
- [ ] GovernanceKernel is sole promotion authority
- [ ] Event log is append-only and totally ordered
- [ ] Replay remains deterministic and authoritative
- [ ] Epistemic monotonicity is preserved
- [ ] Entropy monotonicity is preserved
- [ ] Fail-closed behavior is preserved
- [ ] No probabilistic governance decisions exist
- [ ] No recursive quorum-of-quorums exist
- [ ] No autonomous worker scaling exists
- [ ] All overflow modes are configuration-bound
- [ ] Cross-shard replay is coordinated centrally
- [ ] Artifact lineage is globally consistent
- [ ] Semantic intersection remains strict consensus

---

## 10. CONCLUSION

This plan transforms the runtime from a single-threaded sequential pipeline into a bounded asynchronous distributed system. The transformation preserves every governance guarantee:

- Deterministic
- Observational-only
- Governance-centralized
- Replay-authoritative
- Fail-closed
- Epistemically monotonic

**Workers assist infrastructure. Infrastructure governs truth.**
