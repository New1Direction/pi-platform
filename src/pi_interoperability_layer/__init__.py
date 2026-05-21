"""pi-interoperability-layer: Deterministic interoperability layer for governed semantic runtimes.

Provides canonical artifact contracts, schema registry, event-sourced execution,
runtime interface governance, blast radius formalization, CI/CD integration,
semantic worker mesh orchestration, snapshot registry, query engine, and
visualization layer.

No inference. No LLM calls. No probabilistic scoring.
Infrastructure-grade determinism only.
"""

from pi_interoperability_layer.blast_radius import (
    BlastRadiusEngine,
    BlastRadiusReport,
    BlastRadiusScore,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
)
from pi_interoperability_layer.capability.graph import (
    CompatibilityCheck,
    CompatibilityEdge,
    CompatibilityType,
    CompatibilityVerdict,
    ExtensionCompatibilityGraph,
)
from pi_interoperability_layer.capability.indexing import (
    IndexEntry,
    SemanticIndexWorker,
    SemanticQueryWorker,
)
from pi_interoperability_layer.capability.ingestion import (
    GovernedIngestionPipeline,
    IngestionPhase,
    IngestionReceipt,
    IngestionStep,
)
from pi_interoperability_layer.capability.registry import (
    RegistryEntry,
    RegistryEntryStatus,
    RegistryFingerprints,
    SemanticCapabilityRegistry,
    TrustScore,
    TrustScoringBasis,
)
from pi_interoperability_layer.cicd import (
    ArtifactVerificationResult,
    GitHubActionsWorkflow,
    PolicyEnforcementHook,
    PRGateConfig,
    PRGateResult,
    ReplayValidationGate,
)
from pi_interoperability_layer.contracts import (
    ArtifactContract,
    ArtifactFingerprint,
    ContractRegistry,
    SchemaEvolutionLog,
    SchemaEvolutionRecord,
    SchemaVersion,
    canonical_json,
    compute_fingerprint,
)
from pi_interoperability_layer.execution import (
    EventRecord,
    ExecutionEngine,
    ReplayLedger,
    canonical_event_payload,
)
from pi_interoperability_layer.interfaces import (
    ProvenanceChain,
    ReplaySafeRouter,
    RuntimeMessage,
    WorkerInputEnvelope,
    WorkerOutputEnvelope,
)
from pi_interoperability_layer.queries import (
    SemanticQueryEngine,
    SemanticQueryResult,
)
from pi_interoperability_layer.registry import (
    ReplayBundle,
    RetentionPolicy,
    SnapshotMetadata,
    SnapshotRecord,
    SnapshotRegistry,
)
from pi_interoperability_layer.schema_registry import (
    CompatibilityResult,
    SchemaValidator,
    load_evolution_log,
    load_registry,
    save_evolution_log,
    save_registry,
    schema_identity_hash,
)
from pi_interoperability_layer.visualization import (
    render_diff_heatmap,
    render_governance_dashboard,
    render_topology_graph,
    render_validation_html,
)

__version__ = "0.3.0"
__all__ = [
    "ArtifactContract", "ArtifactFingerprint", "ContractRegistry",
    "SchemaEvolutionLog", "SchemaEvolutionRecord", "SchemaVersion",
    "canonical_json", "compute_fingerprint",
    "CompatibilityResult", "SchemaValidator",
    "load_registry", "save_registry", "load_evolution_log", "save_evolution_log", "schema_identity_hash",
    "EventRecord", "ReplayLedger", "ExecutionEngine", "canonical_event_payload",
    "WorkerInputEnvelope", "WorkerOutputEnvelope", "RuntimeMessage", "ProvenanceChain", "ReplaySafeRouter",
    "TopologyNode", "TopologyEdge", "TopologyGraph", "BlastRadiusScore", "BlastRadiusReport", "BlastRadiusEngine",
    "GitHubActionsWorkflow", "PRGateConfig", "PRGateResult", "ArtifactVerificationResult",
    "ReplayValidationGate", "PolicyEnforcementHook",
    "SnapshotRegistry", "SnapshotRecord", "SnapshotMetadata", "ReplayBundle", "RetentionPolicy",
    "SemanticQueryEngine", "SemanticQueryResult",
    "render_validation_html", "render_diff_heatmap", "render_topology_graph", "render_governance_dashboard",
    "SemanticCapabilityRegistry", "RegistryEntry", "RegistryEntryStatus", "RegistryFingerprints",
    "TrustScore", "TrustScoringBasis",
    "ExtensionCompatibilityGraph", "CompatibilityEdge", "CompatibilityType", "CompatibilityCheck", "CompatibilityVerdict",
    "GovernedIngestionPipeline", "IngestionReceipt", "IngestionStep", "IngestionPhase",
    "SemanticIndexWorker", "SemanticQueryWorker", "IndexEntry",
]
