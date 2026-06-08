# pi-semantic-recon — Architectural Delta Summary

> **Version:** 1.1 (Post-Gap Hardening)
> **Date:** 2026-05-18
> **Scope:** Gaps 1–3 Production Hardening
> **Invariants Preserved:** ALL

---

## 1. ORIGINAL DETERMINISTIC INVARIANTS

The runtime was designed around five non-negotiable architectural constraints:

| Invariant | Enforcement |
|---|---|
| **Observational primacy** | Every semantic claim MUST be bound to observed evidence. Free-floating claims are rejected at the schema gate. |
| **Replay authority** | `REPLAY_CONFIRMED` outranks `INFERRED`. No promotion to `VERIFIED` without replay closure or provenance completeness. |
| **Epistemic monotonicity** | Promotions are append-only. Once `VERIFIED`, never downgraded. Once `REJECTED`, never resurrected. |
| **Governance centrality** | Only `GovernanceKernel` may mutate runtime state. Workers are replaceable pure functions. |
| **Entropy reduction** | Every processing step must reduce or hold semantic entropy. Regrowth triggers `VIOLATION`. |
| **Fail-closed topology** | Unknown conditions HALT. Partial truth is rejected. Speculative continuation is forbidden. |

These invariants were **intentionally preserved** across all Gap 1–3 changes. No semantic capability was added that would weaken them.

---

## 2. WHAT CHANGED — GAP 1: REAL-WORLD PAYLOAD NORMALIZATION

### Problem
The original `IngressParserNode` assumed `body_json` was clean, parsed JSON. Real-world traffic is compressed (gzip, brotli, zstd), encoded (multipart, form-urlencoded), or structured in non-JSON formats (XML, Protocol Buffers, gRPC).

### Solution
Added `PayloadNormalizer` — a deterministic normalization boundary between raw bytes and semantic extraction.

**New capabilities:**
- Compression detection via `Content-Encoding` headers **and** magic-byte heuristics
- Decompression: gzip, deflate, brotli (optional), zstd (optional)
- Format detection: JSON, XML, FORM_URLENCODED, FORM_MULTIPART, TEXT, HTML, BINARY, PROTOBUF, GRPC
- XML → simplified dict conversion (recursive, namespace-aware)
- Form-urlencoded → flat dict conversion
- Protobuf wire-type probing **without schema** (varint, fixed64, length-delimited, 32-bit)
- Charset extraction from `Content-Type` parameters
- Boundary extraction for multipart form data
- Malformed payload survivability (parse failures produce `decoding_errors`, never crash)

**Integration points:**
- `IngressParserNode` now populates `content_meta`, `request_payload_norm`, `response_payload_norm`
- `StructuralExtractorNode` falls back to `parsed_payload` when raw `body_json` parse fails
- `PayloadNormalizer` is **not** a semantic extractor — it is a normalization boundary

### What was preserved
- **Byte-exact envelope hashing:** Raw bytes are ALWAYS preserved in `raw_bytes` for provenance integrity
- **Deterministic replay:** Same compressed payload produces identical normalization results
- **Observational-only:** Format detection uses headers + heuristics, never LLM inference
- **Fail-closed:** Unsupported formats emit `decoding_errors`, never speculative parsing

---

## 3. WHAT CHANGED — GAP 2: MUTATION-AWARE REPLAY SEMANTICS

### Problem
The original `ReplayValidator` assumed state-agnostic idempotency. In reality, many endpoints mutate global state:
- `POST /checkout` → first call: `200 OK`, second call: `409 Conflict` (duplicate transaction)
- `DELETE /resource/123` → first call: `200 OK`, second call: `404 Not Found` (already deleted)

The system previously classified these as `NON_EQUIVALENT` or `AUTH_MUTATION`, when the behavioral change is the **correct** stateful response.

### Solution
Added a 7-class mutation taxonomy to `ReplayValidator`:

| Class | Trigger | Replay Classification |
|---|---|---|
| `IDEMPOTENT_READ` | GET/HEAD with low drift | `REPLAY_EQUIVALENT` |
| `STATEFUL_MUTATION` | POST/PUT/PATCH with status shift indicating state change | `EXPECTED_STATE_TRANSITION` |
| `DESTRUCTIVE_MUTATION` | DELETE with 404-on-replay | `EXPECTED_STATE_TRANSITION` |
| `NON_DETERMINISTIC` | GET/HEAD with high drift on stable endpoint | `SEMANTIC_DIVERGENCE` |
| `REPLAY_UNSAFE` | Externally annotated (payments, auth) | `SKIP_REPLAY` |
| `SIDE_EFFECT_BOUND` | Observable side effects (webhooks, emails) | `NON_EQUIVALENT` |
| `UNKNOWN` | Insufficient evidence | `NON_EQUIVALENT` |

**Critical design constraint:**
`REPLAY_UNSAFE` is **externally set** by pipeline annotation, never inferred. This prevents the validator from silently assuming safety for unknown endpoints.

**Integration points:**
- New method: `compare_with_mutation_context(original_trace, replay_trace, mutation_class)`
- Auth drift remains an **independent dimension** — mutation classification does NOT conflate with auth mutation detection
- Stateful divergence after successful prior mutation may classify as `EXPECTED_STATE_TRANSITION`, not `NON_EQUIVALENT`

### What was preserved
- **Observational-only:** Mutation class is derived from `method + status_code + response_fingerprint`, never from endpoint naming
- **Replay authority remains absolute:** Only `REPLAY_CONFIRMED` promotes to `VERIFIED`. Mutation awareness changes equivalence classification, not epistemic promotion rules
- **No speculative downgrading:** Destructive divergence is NEVER silently downgraded to equivalence
- **Deterministic:** Same (trace, mutation_class) input always produces same classification

---

## 4. WHAT CHANGED — GAP 3: DISTRIBUTED BOUNDS MIGRATION

### Problem
All validators had hardcoded constants: `MAX_NODES = 64`, `MAX_CLAIMS = 512`, `MAX_WINDOW_SIZE = 32`. These bounds kept unit tests deterministic and fast, but would trigger `HALT` instantly on enterprise-scale microservice meshes (Netflix, Uber).

### Solution
Added `ValidationBoundsConfig` — a 16-limit configuration model injected into all validators:

| Limit | Default | Governs |
|---|---|---|
| `max_fsm_nodes` | 64 | FSM graph nodes |
| `max_fsm_edges` | 256 | FSM graph edges |
| `max_fsm_fanout` | 8 | Per-node outgoing edges |
| `max_fsm_depth` | 6 | Longest path in FSM |
| `max_provenance_depth` | 32 | Ancestry chain traversal |
| `max_replay_drift_score` | 1.0 | Semantic diff tolerance |
| `max_quorum_claims` | 512 | Claims per quorum execution |
| `max_quorum_intersections` | 256 | Intersection operations |
| `max_quorum_promotion_depth` | 4 | Promotion rule applications |
| `max_entropy_window_size` | 32 | Stability window snapshots |
| `max_entropy_structural_nodes` | 64 | Structural entropy node count |
| `max_entropy_semantic_conflicts` | 16 | Conflict set size |
| `max_entropy_auth_bindings` | 16 | Auth correlation count |
| `max_entropy_fsm_nodes` | 64 | FSM node entropy budget |
| `max_entropy_convergence_history` | 6 | Convergence scoring depth |
| `max_auth_evidence_per_packet` | 16 | Auth evidence per packet |

**Overflow behavior support:**
- `truncate` — trim to bound, emit `VIOLATION`
- `shard` — partition workload, preserve deterministic semantics
- `halt` — hard stop (default for critical paths)
- `degrade-observability-only` — continue with reduced confidence, never promote

**Integration points:**
- `PipelineDriver.__init__()` accepts optional `bounds` parameter
- All 6 validators receive `bounds` via constructor injection
- Removed dead second `__init__()` from `SemanticQuorum` that shadowed bounds injection

### What was preserved
- **Fail-closed:** Default behavior remains `HALT`. Bounds expansion requires explicit configuration
- **Deterministic:** Same `bounds` + same input = same output
- **No autonomous scaling:** Overflow modes are externally configured, never self-selected
- **Governance centrality:** Kernel still owns all epistemic promotion; bounds only affect validator capacity

---

## 5. WHAT CAPABILITIES EXPANDED

| Capability | Before | After |
|---|---|---|
| Payload formats | JSON only | JSON, XML, form, multipart, protobuf wire probe, text, html, binary |
| Compression | None | gzip, deflate, brotli, zstd |
| Replay awareness | Stateless idempotency | 7-class mutation taxonomy |
| Scale bounds | Hardcoded 64/256/512 | Configurable 16-limit model |
| Overflow handling | HALT only | truncate / shard / halt / degrade |
| Content negotiation | None | charset, boundary, encoding, transfer-encoding |
| Malformed survivability | Crash | Graceful error tagging |
| Protobuf without schema | Unsupported | Wire-type field count + structure |

---

## 6. WHAT REMAINS INTENTIONALLY UNSUPPORTED

These are **not gaps**. They are **architectural exclusions**:

| Exclusion | Rationale |
|---|---|
| **LLM-driven format inference** | Would violate observational primacy. Format detection is header + heuristic only. |
| **Protobuf schema inference** | Schema-free protobuf parsing is undecidable. Wire probe is the deterministic boundary. |
| **Autonomous endpoint classification** | Mutation class is observational (method + status + fingerprint), never inferred from naming or documentation. |
| **Probabilistic quorum voting** | Semantic intersection remains strict type consensus. No majority voting. No confidence-weighted blending. |
| **Self-modifying bounds** | Bounds are configuration, never runtime-adaptive. No feedback-loop scaling. |
| **Recursive quorum-of-quorums** | Prohibited by governance topology. Shards do not form nested quorums. |
| **Autonomous worker spawning** | Workers are replaceable pure functions. No self-replication. |
| **Speculative continuation past HALT** | Fail-closed is absolute. No degraded-truth mode for critical paths. |

---

## 7. WHY THESE CHANGES MATTER

### Replay-Aware Mutation Classification
Without it, the runtime would systematically misclassify correct API behavior as protocol violations. A `409 Conflict` on duplicate `POST /checkout` is not a bug — it is the **correct stateful response**. The old system would have emitted `NON_EQUIVALENT` and potentially blocked promotion of the entire endpoint's semantics. The new system recognizes `EXPECTED_STATE_TRANSITION` and isolates the classification to the mutation dimension, preserving the rest of the endpoint's semantic extraction.

### Payload Normalization Preserves Provenance
Decompression does not destroy the original envelope. `raw_bytes` is always preserved. The envelope hash is computed on the **original** bytes, not the decompressed content. This means replay verification remains byte-exact at the transport layer, while semantic extraction operates on the normalized content. The two layers never conflate.

### Hardcoded Constants Were Removed
Hard bounds are appropriate for unit tests but catastrophic for production. A 500-service microservice mesh will have >64 distinct endpoint states. The old system would HALT. The new system allows bounds configuration with explicit overflow modes, enabling horizontal sharding without breaking deterministic semantics.

---

## 8. SEMANTIC COGNITION VS. INFRASTRUCTURE

**Unchanged principle:**

> Semantic cognition assists infrastructure. Infrastructure remains authoritative.

- The `PayloadNormalizer` does not "understand" XML or protobuf. It normalizes them into structures the semantic pipeline can process.
- The `ReplayValidator` does not "infer" endpoint behavior. It classifies observed behavior from replay evidence.
- The `SemanticQuorum` does not "negotiate" meaning. It intersects evidence-bound claims deterministically.
- The `GovernanceKernel` does not "learn" policies. It executes constitutional transition rules.

**Any feature that would shift authority from infrastructure to inference was rejected.**

---

## 9. EPISTEMIC SEPARATION PRESERVED

The three layers of truth remain strictly separated:

| Layer | Source | Promotion Path |
|---|---|---|
| **Runtime truth** | Observed packets, headers, bytes | `OBSERVED` → `INFERRED` (with evidence) |
| **Semantic truth** | Intersection of evidence-bound claims | `INFERRED` → `VERIFIED` (with replay) |
| **Verified truth** | Replay-confirmed, provenance-closed | `VERIFIED` → `REPLAY_CONFIRMED` (with exact replay) |

Payload normalization adds a **fourth storage layer** (raw bytes), but does not create a new epistemic state. Raw bytes are observational evidence, not semantic claims.

---

## 10. CONCLUSION

Gaps 1–3 expanded the runtime's **operational envelope** without weakening its **governance guarantees**:

- **Gap 1:** Real-world traffic is now survivable (compression, alternative formats, malformed payloads)
- **Gap 2:** Stateful replay is now correctly classified (mutation taxonomy, expected transitions)
- **Gap 3:** Scale is now configurable (bounds injection, overflow modes, sharding primitives)

All original invariants hold. The system remains:
- Deterministic
- Observational-only
- Governance-centralized
- Replay-authoritative
- Fail-closed
- Epistemically monotonic

**Next phase:** Production-scale bottleneck analysis and distributed execution migration plan.
