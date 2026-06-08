# pi-extension-governor Architecture

## Vision

A **governed extension ecosystem** that safely ingests, normalizes, sandboxes, validates,
and governs external extensions before they enter the semantic worker mesh.

External packages are **NOT trusted execution units**.
They are raw semantic material that must be normalized into governed worker contracts.

## Core Philosophy

semantic cognition assists infrastructure — it does not replace infrastructure.

## Governance Invariants

- deterministic execution
- replay authority
- provenance lineage
- bounded semantics
- centralized orchestration
- validation-before-mutation
- non-self-modifying worker rules

## Subsystem Components

### 1. Extension Manifest System

**File:** `manifest.py`

Deterministic manifest schema with required fields:
- `extension_id`, `package_name`, `package_version`, `package_hash`
- `capability_class` (openapi_tooling, graphql_tooling, kubernetes_manifest, terraform_analysis, cicd_integration, visualization, observability_adapter, static_analyzer)
- `declared_inputs`, `declared_outputs`
- `network_access`, `filesystem_access`, `subprocess_access`, `dynamic_eval_access`, `thread_spawn_access`
- `deterministic_claim`, `replayability_claim`
- `resource_cpu_ms_max`, `resource_memory_mb_max`, `resource_output_size_max`
- `trust_zone` (CORE_TRUSTED, GOVERNED_EXTENSION, SANDBOX_EXPERIMENTAL)
- `status` lifecycle: PENDING_INSPECTION -> STATIC_ANALYZED -> DETERMINISM_VERIFIED -> SEMANTIC_NORMALIZED -> POLICY_APPROVED -> ADMITTED / REJECTED / QUARANTINED

Manifests are immutable (Pydantic frozen). Hash computed deterministically.

### 2. Static Capability Inspector

**File:** `inspector.py`

AST-based static analysis BEFORE execution:
- Dangerous import detection (subprocess, socket, eval, exec, ctypes, threading, etc.)
- Obfuscation pattern detection (base64 decode, zlib decompress, etc.)
- Telemetry pattern detection
- Network call detection
- Subprocess spawn detection
- Dynamic execution detection (eval/exec/compile)
- File operation detection (write modes, os.remove, shutil.rmtree)
- Thread/process spawn detection

Classification output:
- DETERMINISTIC_SAFE
- NON_DETERMINISTIC
- REPLAY_UNSAFE
- TELEMETRY_RISK
- POLICY_VIOLATION
- REJECTED

No execution of untrusted code.

### 3. Sandboxed Extension Runtime

**File:** `sandbox.py`

Bounded execution environment:
- CPU time limit (SIGALRM)
- Memory limit (RLIMIT_AS)
- Output size limit
- Restricted builtins (no network, no file write, no subprocess)
- Determinism verification (same input -> same output hash, 3 runs)

Result status: SUCCESS, TIMEOUT, MEMORY_EXCEEDED, EXCEPTION, REJECTED

**Warning:** Production must use proper sandboxing (seccomp, namespaces, containers).
This implementation provides resource ceilings as a deterministic baseline.

### 4. Determinism Verification Worker

**File:** `sandbox.py` (verify_determinism method)

Runs identical extension executions multiple times.
Same input -> same output hash required.

If outputs drift:
- extension rejected
- provenance receipt generated
- determinism violation recorded

### 5. Semantic Output Normalization

**File:** `normalizer.py`

Converts external extension outputs into canonical semantic graph artifacts.

Canonical artifact types accepted by the mesh:
- SemanticIRTrace
- DependencyGraph
- ReplaySurfaceReport
- ComplianceArtifact
- TopologyGraph
- BoundaryValidationReport
- TelemetryExposureReport
- ObservabilityDriftReport
- SecuritySimulationReport
- SensitiveFlowReport

No arbitrary schemas allowed into the mesh.
Unknown artifact types are rejected with `NormalizationRejection`.

### 6. Extension Governance Policy Engine

**File:** `policy.py`

Org-level deterministic policy rules:
- approved capability classes
- banned imports
- maximum execution ceilings
- replay restrictions
- trust zones
- allowed telemetry surfaces

Policy rule types:
- required_capability
- max_resource
- trust_zone_restriction
- banned_capability

Evaluation output: passed/failed with per-rule detail.

### 7. Extension Provenance Ledger

**File:** `provenance.py`

Append-only execution receipts with chain hashing.

Each receipt contains:
- receipt_id, extension_id, package_hash
- worker_contract_version
- execution_duration_ms, output_hash
- deterministic_fingerprint
- replay_lineage
- previous_receipt_hash, receipt_hash

Chain integrity verified with `verify_chain()`.

### 8. Ecosystem Trust Zone Enforcement

**File:** `trust_zones.py`

Three trust zones:
- CORE_TRUSTED: explicit allowlist only
- GOVERNED_EXTENSION: standard admission path
- SANDBOX_EXPERIMENTAL: default for untrusted; NEVER gains governance authority

Rules:
- Experimental packages remain experimental
- Core trusted requires explicit package hash allowlist
- Experimental packages can NEVER gain governance authority

### 9. Extension Governor Pipeline

**File:** `governor.py`

Central admission authority. Six-phase lifecycle:

1. **Static Inspection:** AST-based source analysis
2. **Determinism Verification:** 3-run identical input/output hash verification
3. **Semantic Normalization:** Convert to canonical artifact types
4. **Policy Evaluation:** Evaluate against governance policy rules
5. **Trust Zone Assignment:** Determine trust zone
6. **Admission Decision:** Admit or reject with provenance receipt

## Integration Points

The extension governor integrates with:
- `pi-interoperability-layer` mesh (ArtifactBus, OrchestrationLedger)
- `pi-semantic-recon` (consumes SemanticIRTrace)
- `pi-semantic-validator` (provides BoundaryValidationReport)
- `pi-semantic-radius` (provides TopologyGraph)

## Controlled Capability Expansion

Approved ecosystem ingestion targets:
- OpenAPI tooling
- GraphQL tooling
- Kubernetes manifests
- Terraform analysis
- CI/CD integrations
- Visualization tooling
- Observability adapters
- Static analyzers

Explicitly NOT evolving toward:
- autonomous planners
- recursive agent swarms
- self-modifying workers
- emergent orchestration
- decentralized consensus systems

## Test Coverage

36 tests covering:
- Manifest determinism and immutability
- Static inspection (eval, subprocess, network, file write, safe code)
- Sandbox execution, timeout, output size, determinism verification
- Policy evaluation (allows, rejects network/subprocess/experimental)
- Semantic normalization (accepts canonical, rejects unknown)
- Provenance ledger (append, verify chain, lineage)
- Trust zone enforcement (experimental stays experimental, core requires allowlist)
- Governor integration (admits safe, rejects eval, rejects non-deterministic, rejects policy violation, rejects unknown artifact type)

## Governance Invariants (Preserved)

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
- zero recursive spawning
- no decentralized planning
- no emergent behavior

No LLM calls. No inference. No probabilistic scoring.
Infrastructure-grade semantic execution only.
