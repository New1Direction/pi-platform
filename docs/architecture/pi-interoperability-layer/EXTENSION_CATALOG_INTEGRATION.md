# Pi Extension Catalog Integration Architecture

## Purpose

The `pi-extension-catalog-integration` layer bridges the external npm-backed Notte
Pi Package Catalog (~2,800+ packages) into the governed semantic capability mesh.

All external packages become constrained capability modules.
Modules become composable deterministic workers.
Workers form validated execution graphs.
Graphs become CI/CD enforceable systems intelligence.

## Pipeline

```
Notte Catalog → Ingest → Classify → Policy Gate → Sandbox Validate
              → Normalize → Dependency Expand → Registry
```

## Workers

### 1. PackageCatalogIngestWorker
- Pulls from Notte `pi-packages-catalog` function
- search mode: package discovery with pagination
- details mode: single package metadata extraction
- Normalizes npm metadata into `ExtensionManifest`
- Receipts with chain hashing

### 2. CapabilityClassifierWorker
- Rule-based keyword classification (zero LLM)
- Dependency-based class inference
- Evidence-bound classification results
- Maps packages → `CapabilityClass` taxonomy

### 3. PackagePolicyGateWorker
- Applies `ExtensionGovernancePolicy` to external packages
- Forbidden import detection
- Zone restriction enforcement
- Telemetry surface review
- Deterministic pass/fail with violation evidence

### 4. SandboxValidationWorker
- Executes package source in `SandboxedExtensionRuntime`
- Determinism verification
- Replay safety proof
- CPU/memory/output bounds enforcement
- No production replay — sandbox only

### 5. PackageNormalizationWorker
- Converts external outputs into canonical semantic artifacts
- Schema-bound artifact types
- Rejection receipts for unknown schemas
- Deterministic artifact hashing

### 6. DependencyGraphExpansionWorker
- Maps npm dependencies to `CompatibilityEdge` declarations
- `DEPENDS_ON` edges with capability class metadata
- Missing dependency recording
- No install-time validation here — that belongs in the pipeline

### 7. CapabilityCompositionPlanner
- Builds deterministic DAGs of workers/packages
- Topological phase ordering
- Cycle detection
- Conflict-aware phase separation
- Outputs graph only — zero execution autonomy

## Integration Points

### Notte API
- API key: `NOTTE_API_KEY` environment variable only
- No hardcoded credentials
- Function ID: `71b6214f-16c4-4702-b0c3-b3c948debf8a`
- Endpoints: `search`, `details`

### Registry
- `SemanticCapabilityRegistry` admits external packages with full fingerprints
- `TrustScore` computed from policy + sandbox evidence
- `RegistryEntryStatus.ACTIVE` only after full pipeline pass

### Compatibility Graph
- `ExtensionCompatibilityGraph` extended with `check_compatibility()`
- External package edges merged with internal edges
- Deterministic topological ordering preserved

## Governance Invariants

- deterministic execution only
- no LLM inference inside workers
- no probabilistic scoring
- no autonomous or recursive spawning
- no stealth, evasion, or anti-forensics behavior
- all outputs deterministic and replay-safe
- all external packages sandbox-validated before registration
- validation before mutation
- fail-closed behavior

## CI/CD Gating

The `CatalogIntegrationPipeline` produces a `PipelineReceipt` with:
- `pipeline_hash`: chain hash of all phase receipts
- `evidence_chain`: ordered list of all validation results
- `final_status`: `ADMITTED` or `REJECTED`
- `trust_score`: evidence-based scoring for registry admission

CI/CD systems can gate on `final_status == "ADMITTED"` and
`pipeline_hash` for reproducible builds.

## File Map

```
src/pi_interoperability_layer/catalog/
├── __init__.py                  # Exports
├── notte_client.py              # Notte API client
├── ingest_worker.py             # Catalog ingest
├── classifier_worker.py         # Capability classification
├── policy_gate_worker.py        # Policy enforcement
├── sandbox_worker.py            # Sandbox validation
├── normalization_worker.py      # Artifact normalization
├── dependency_expansion_worker.py # Graph edge construction
├── composition_planner.py       # DAG composition
└── pipeline.py                  # End-to-end pipeline
tests/test_catalog_integration.py # 23 tests
```
