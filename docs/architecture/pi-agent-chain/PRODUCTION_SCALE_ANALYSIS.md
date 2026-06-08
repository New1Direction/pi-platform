# pi-semantic-recon — Production-Scale Bottleneck Analysis

> **Version:** 1.0
> **Date:** 2026-05-18
> **Scope:** Identifying architectural limits before distributed migration
> **Constraint:** All mitigations must remain deterministic. No probabilistic governance.

---

## EXECUTIVE SUMMARY

The runtime is currently single-threaded, SQLite-backed, and in-memory bound. At enterprise scale (Netflix, Uber, AWS-level API traffic), ten specific bottlenecks will trigger cascading failures. Each bottleneck has a deterministic mitigation path. None require probabilistic governance, autonomous orchestration, or majority-vote semantics.

**Critical rule:** If a mitigation would make any governance decision probabilistic, it is rejected.

---

## BOTTLENECK 1: SQLITE/GLOBAL LEDGER CONTENTION

### Failure Mode
`StateLedger` uses SQLite with exclusive locking. Under concurrent packet ingestion from multiple acquisition workers, `BEGIN EXCLUSIVE` transactions serialize all writes. Workers stall waiting for lock release. Throughput collapses to ~50-100 packets/second regardless of CPU capacity.

### Scaling Threshold
- Collapse begins: ~500 packets/second sustained
- Complete stall: ~2000 packets/second with 10+ workers
- Recovery: requires ledger restart; queued packets may exceed memory

### Architectural Risk
- **Cascading timeout:** Replay validation queues back up. Entropy windows grow unbounded. Stability checks fail.
- **Deterministic ordering violation:** If workers implement retry logic, packet processing order becomes non-deterministic.
- **Governance HALT:** If entropy exceeds bounds before writes complete, kernel triggers global HALT.

### Deterministic Mitigation Path
1. **Shard ledger by execution_id:** Each execution trace gets its own SQLite file or WAL segment. Cross-trace reads use a read-only view aggregator.
2. **Append-only journal pattern:** Replace `UPDATE` with `INSERT` + tombstone. SQLite handles append-only writes with far less contention.
3. **Time-bounded leases:** Workers hold packet processing leases (e.g., 30s). Lease expiry triggers deterministic reassignment, not probabilistic retry.

### What Must NEVER Become Probabilistic
- Packet ordering within an execution trace
- Epistemic promotion timestamps
- Provenance chain sequence numbers

---

## BOTTLENECK 2: SINGLE-THREADED VALIDATOR EXECUTION

### Failure Mode
All 6 verification phases execute sequentially in `PipelineDriver._verify()`. On a 64-core machine, only 1 core is utilized. A large trace (10K packets) may spend 15+ minutes in verification while the acquisition pipeline idles.

### Scaling Threshold
- Linear degradation: >100 packets/trace
- Prohibitive latency: >1000 packets/trace (30+ minutes verification)
- Operational death: >10K packets/trace (hours of CPU time)

### Architectural Risk
- **Backpressure amplification:** Acquisition workers continue ingesting while verification lags. Memory pressure builds.
- **Stale entropy analysis:** FSM and auth reports computed on partially-processed traces produce incorrect governance decisions.
- **Timeout cascades:** Replay validation depends on live endpoint availability. Long verification delays mean replay attempts occur against changed systems.

### Deterministic Mitigation Path
1. **Phase-parallel execution:** Phases 1-3 (Provenance, Replay, Auth) are independent and can execute in parallel. Phase 4 (State Transition) depends on Phase 3 output. Phase 5 (Quorum) depends on Phase 1-4. Phase 6 (Entropy) depends on all prior.
2. **Trace-parallel execution:** Different execution traces are independent. Worker pool processes traces in parallel with deterministic routing (e.g., ` execution_id % num_workers`).
3. **Bounded worker pools:** Fixed-size pools (never auto-scaling). Each worker is a replaceable pure function.

### What Must NEVER Become Probabilistic
- Phase ordering (Provenance → Replay → Auth → State → Quorum → Entropy)
- Promotion rules applied to a given claim
- Epistemic state transitions

---

## BOTTLENECK 3: IN-MEMORY ARTIFACT BOTTLENECKS

### Failure Mode
`ArtifactRegistry` stores all artifacts in memory (`:memory:` SQLite or Python dict). At scale, artifact sets for large microservices consume gigabytes of RAM. Python's GIL prevents efficient memory reclamation.

### Scaling Threshold
- Moderate pressure: ~10K artifacts (~200MB)
- Severe pressure: ~100K artifacts (~2GB)
- OOM kill: ~500K artifacts (~10GB+ with Python overhead)

### Architectural Risk
- **Provenance traversal amplification:** Checking artifact ancestry requires walking parent chains. Deep chains in large registries become O(n^2) operations.
- **GC storms:** Python garbage collection pauses during large artifact creation bursts.
- **Serialization overhead:** Saving registry state for crash recovery requires serializing all artifacts.

### Deterministic Mitigation Path
1. **Tiered storage:** Hot artifacts (last 1 hour) in memory. Warm artifacts (last 24 hours) in SQLite on NVMe. Cold artifacts in object storage (S3/MinIO) with deterministic retrieval keys.
2. **Artifact pagination:** Provenance validation paginates ancestry walks (e.g., max 32 ancestors per query).
3. **Immutable artifact compaction:** Old `OBSERVED` artifacts that were never promoted are archived deterministically (e.g., after 7 days, based on timestamp, not usage heuristics).

### What Must NEVER Become Probabilistic
- Artifact identity (artifact_id hashing)
- Ancestry chain integrity
- Retrieval from cold storage (must be deterministic key-based, not cache-probabilistic)

---

## BOTTLENECK 4: REPLAY QUEUE SERIALIZATION LIMITS

### Failure Mode
`ReplayValidator` sends replay requests synchronously. Each replay blocks until the endpoint responds. With 1000 packets and 500ms average response time, replay alone takes 8+ minutes sequentially.

### Scaling Threshold
- Acceptable: <50 replays/trace
- Degraded: 50-500 replays/trace
- Unusable: >500 replays/trace

### Architectural Risk
- **Endpoint rate limiting:** Replaying against production APIs triggers rate limits, causing 429/503 responses that are misclassified as replay divergence.
- **Temporal drift:** Long replay sequences span significant time. The system under test may change mid-replay.
- **Auth token expiry:** Session tokens used for replay may expire during long queues.

### Deterministic Mitigation Path
1. **Batch replay with identity hashing:** Group replay-identical packets (same method, path, normalized payload) and replay once. Result propagates to all group members.
2. **Replay scheduling windows:** Limit replay execution to bounded time windows (e.g., 60s max). Unreplayed packets get `REPLAY_PENDING` state, not speculative classification.
3. **Replay worker isolation:** Dedicated replay worker pool with fixed concurrency (e.g., 10 concurrent replays). No dynamic scaling.

### What Must NEVER Become Probabilistic
- Replay grouping criteria (must be byte-exact or hash-identical)
- Replay result classification
- Timeout handling (must be deterministic, not adaptive)

---

## BOTTLENECK 5: ENTROPY ANALYSIS SCALING CONSTRAINTS

### Failure Mode
`EntropyAnalysisValidator.compute_composite_entropy()` iterates over all struct nodes, all semantic conflicts, all auth bindings, and all FSM nodes for every snapshot. Complexity is O(S × (N_struct + N_conflict + N_auth + N_fsm)) where S is snapshot count.

### Scaling Threshold
- Acceptable: S=32, N_struct=64, N_conflict=16
- Degraded: S=128, N_struct=256, N_conflict=64
- Unusable: S=512, N_struct=1024, N_conflict=256

### Architectural Risk
- **Snapshot flooding:** Under high packet volume, the stability window fills continuously. Each new snapshot triggers full re-computation.
- **Convergence false-positives:** Slow entropy computation delays convergence detection, causing unnecessary HALT triggers.
- **Memory bloat:** Each snapshot stores deep copies of all component metrics.

### Deterministic Mitigation Path
1. **Incremental entropy updates:** Delta entropy between snapshots T and T-1, not full re-computation. Store running sums, update on change.
2. **Hierarchical entropy:** Compute endpoint-level entropy first. Only drill into endpoint details if endpoint-level entropy changes.
3. **Snapshot decimation:** Retain every Nth snapshot for historical analysis (e.g., keep 32, decimate older ones). Deterministic decimation (power-of-2 intervals).

### What Must NEVER Become Probabilistic
- Entropy monotonicity check
- Convergence scoring
- Drift detection thresholds

---

## BOTTLENECK 6: FSM GRAPH MEMORY PRESSURE

### Failure Mode
`StateTransitionValidator.extract_fsm()` builds a directed graph of all observed state transitions. Enterprise microservices have hundreds of endpoints, each with multiple states (healthy, degraded, error, maintenance). The FSM grows exponentially with endpoint count.

### Scaling Threshold
- Default bounds: 64 nodes, 256 edges
- Realistic enterprise: 500+ endpoints × 4 states = 2000+ nodes
- Unbounded: 10K+ nodes, 50K+ edges

### Architectural Risk
- **Graph traversal explosion:** Pathfinding and cycle detection become O(V×E) or worse.
- **Serialization overhead:** Saving FSM state for checkpointing requires serializing the entire graph.
- **Visualization impossibility:** Human review of 2000-node FSMs is impractical.

### Deterministic Mitigation Path
1. **Endpoint-partitioned FSMs:** One FSM per endpoint, not one global FSM. Cross-endpoint dependencies tracked separately.
2. **State abstraction:** Collapse equivalent states (e.g., all 4xx/5xx into `ERROR` super-state) using deterministic rules, not clustering heuristics.
3. **FSM pagination:** Only keep active endpoints in memory. Archive endpoint FSMs after N days of inactivity.

### What Must NEVER Become Probabilistic
- State equivalence determination (must be rule-based: status code ranges, not similarity scores)
- Transition legality (must be observed, not inferred)
- FSM partitioning (must be hash-based, not load-balanced)

---

## BOTTLENECK 7: SEMANTIC QUORUM FAN-IN COSTS

### Failure Mode
`SemanticQuorum.execute()` intersects claims across all artifacts. Intersection is O(C × A) where C is claims per artifact and A is artifact count. With 512 claims and 100 artifacts, this is 51K operations. With 2048 claims and 500 artifacts, this is 1M+ operations.

### Scaling Threshold
- Default bounds: 512 claims, 256 intersections
- Degraded: 2048 claims, 1024 intersections
- Unusable: 8192 claims, 4096 intersections

### Architectural Risk
- **Quorum latency:** Large quorum executions block the entire pipeline.
- **Conflict set explosion:** Many claims on the same property_path create large conflict sets that must be fully enumerated.
- **Memory pressure:** Each intersection produces intermediate sets that must be held in memory.

### Deterministic Mitigation Path
1. **Property-path sharding:** Group claims by property_path hash. Execute quorum per property_path shard in parallel.
2. **Claim deduplication:** Before intersection, deduplicate identical (property_path, inferred_type) claims with deterministic identity hashing.
3. **Bounded conflict enumeration:** Conflict sets larger than max_entropy_semantic_conflicts are truncated with `CONFLICT_SET_OVERFLOW` violation.

### What Must NEVER Become Probabilistic
- Intersection algorithm (strict type consensus, not majority voting)
- Conflict resolution (no confidence-weighted blending)
- Claim identity (must be hash-based on exact content)

---

## BOTTLENECK 8: CROSS-SHARD REPLAY CONSISTENCY

### Failure Mode
When traces are sharded across workers, replay validation may execute against the same endpoint from different workers concurrently. The endpoint's state changes between replays, causing divergent classifications for the same packet across shards.

### Scaling Threshold
- Appears at: >1 worker with replay enabled
- Critical at: >10 workers replaying against stateful endpoints
- Disaster at: workers replay against endpoints with rate-limiting or anti-replay protections

### Architectural Risk
- **Classification inconsistency:** Same packet gets `REPLAY_EQUIVALENT` from Worker A and `NON_EQUIVALENT` from Worker B.
- **Quorum corruption:** Inconsistent replay results fed into quorum produce unstable intersection outputs.
- **Provenance forks:** A single artifact with conflicting replay evidence has ambiguous ancestry.

### Deterministic Mitigation Path
1. **Replay authority centralization:** One dedicated replay worker (or serialized replay queue) handles ALL replays. Results are broadcast to all shards.
2. **Replay snapshot isolation:** Before replaying a batch, capture endpoint state fingerprint (e.g., health check response). Replay batch uses the same state context.
3. **Deterministic replay scheduling:** Replays scheduled at deterministic intervals (e.g., every 60s), not on-demand. Reduces temporal variance.

### What Must NEVER Become Probabilistic
- Replay result classification
- Which worker performs replay
- Replay ordering

---

## BOTTLENECK 9: ARTIFACT LINEAGE AMPLIFICATION

### Failure Mode
Every artifact stores `parent_ids` referencing prior artifacts. In a long-running session, artifact N references artifacts N-1, N-2, ... N-k. Provenance validation walks this chain. The chain length grows linearly with session duration. Amortized cost per validation is O(k), where k grows without bound.

### Scaling Threshold
- Acceptable: k < 32 (current max_provenance_depth)
- Degraded: 32 < k < 128
- Unusable: k > 128 (deep recursion, memory blow-up)

### Architectural Risk
- **Validation latency:** Each new artifact triggers full provenance walk. Linear growth means linearly-slower validation.
- **Circular reference potential:** Bugs in artifact creation could create cycles. Cycle detection is O(k) per validation.
- **Serialization bloat:** Saving artifacts includes saving all parent references.

### Deterministic Mitigation Path
1. **Checkpoint artifacts:** Every N artifacts, create a `CHECKPOINT` artifact that compresses ancestry into a single hash. Subsequent artifacts reference the checkpoint, not the full chain.
2. **Ancestry truncation:** Provenance validation truncates at `max_provenance_depth`. Deeper ancestry is opaque but hash-verifiable.
3. **Deterministic archival:** Archive artifacts older than time threshold (e.g., 30 days). Archive includes full chain hash for verification, but chain is not traversed.

### What Must NEVER Become Probabilistic
- Ancestry chain integrity
- Checkpoint hashing
- Archive/restore decisions

---

## BOTTLENECK 10: DISTRIBUTED PROVENANCE SYNCHRONIZATION

### Failure Mode
In a distributed deployment, artifacts created on Worker A must be visible to Worker B for quorum and provenance validation. Distributed artifact registry introduces CAP theorem trade-offs. Consistency requires coordination; availability requires partitioning.

### Scaling Threshold
- Appears at: 2+ workers with shared registry
- Critical at: 10+ workers across availability zones
- Disaster at: network partitions between workers

### Architectural Risk
- **Split-brain artifact creation:** Workers A and B create artifacts with the same logical identity but different content during a partition.
- **Stale quorum inputs:** Quorum on Worker B uses artifacts from Worker A that are 30 seconds old. Newer artifacts exist but haven't propagated.
- **Provenance gaps:** An artifact references a parent that exists on Worker A but not yet on Worker B. Validation fails with `ORPHANED_ARTIFACT`.

### Deterministic Mitigation Path
1. **Event-sourced artifact log:** All artifact creation events append to a distributed log (Kafka, NATS JetStream, or Raft-backed log). Workers consume the log in order. Deterministic replay of the log reproduces the exact registry state.
2. **Artifact batching:** Workers batch artifact creation (e.g., every 5 seconds). Batches are atomic. Quorum validation uses complete batches, not partially-propagated artifacts.
3. **Deterministic conflict resolution:** If split-brain occurs, deterministic rule resolves (e.g., lower worker_id wins, or lexicographically-first artifact_id wins). NEVER probabilistic merge.

### What Must NEVER Become Probabilistic
- Artifact total ordering
- Conflict resolution rules
- Log replay semantics
- Quorum input completeness

---

## SUMMARY MATRIX

| # | Bottleneck | First Failure | Deterministic Mitigation | Governance Impact |
|---|---|---|---|---|
| 1 | SQLite contention | 500 pkt/s | Shard by execution_id | None |
| 2 | Single-threaded validation | 100 pkt/trace | Phase/trace parallelism | Phase ordering preserved |
| 3 | In-memory artifacts | 10K artifacts | Tiered storage | Hash integrity preserved |
| 4 | Replay serialization | 50 replays/trace | Batch + identity hash | Classification preserved |
| 5 | Entropy computation | 128 snapshots | Incremental updates | Monotonicity preserved |
| 6 | FSM growth | 64 nodes | Endpoint-partitioned FSMs | Transition legality preserved |
| 7 | Quorum fan-in | 512 claims | Property-path sharding | Intersection preserved |
| 8 | Cross-shard replay | 2+ workers | Centralized replay worker | Authority preserved |
| 9 | Lineage depth | 32 ancestors | Checkpoint artifacts | Chain integrity preserved |
| 10 | Provenance sync | 2+ workers | Event-sourced log | Total ordering preserved |

---

## WHAT WAS EXPLICITLY REJECTED

These approaches were considered and rejected because they introduce probabilistic or autonomous behavior:

| Approach | Rejection Reason |
|---|---|
| **Autonomous worker scaling** | Workers must be replaceable pure functions, not self-spawning agents |
| **Probabilistic cache eviction** | Artifact storage decisions must be deterministic (time-based or hash-based) |
| **Majority-vote conflict resolution** | Semantic intersection requires strict consensus, not probabilistic blending |
| **Adaptive timeout tuning** | Timeouts must be configuration-bound, not learned from historical patterns |
| **Self-modifying execution graph** | Pipeline topology is constitutional, not adaptive |
| **Recursive quorum-of-quorums** | Prohibited by governance topology. Shards do not form nested quorums. |
| **LLM-driven bottleneck prediction** | Infrastructure scaling must be rule-based, not inferred |

---

## CONCLUSION

All ten bottlenecks have deterministic mitigation paths. None require weakening governance guarantees. The next phase (async/distributed execution migration) will operationalize these mitigations into a concrete architecture.
