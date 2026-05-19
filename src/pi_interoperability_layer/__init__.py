"""pi-interoperability-layer: Deterministic interoperability layer for governed semantic runtimes.

Provides canonical artifact contracts, schema registry, event-sourced execution,
runtime interface governance, blast radius formalization, CI/CD integration,
semantic worker mesh orchestration, snapshot registry, query engine, and
visualization layer.

No inference. No LLM calls. No probabilistic scoring.
Infrastructure-grade determinism only.
"""

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
from pi_interoperability_layer.schema_registry import (
    CompatibilityResult,
    SchemaValidator,
    load_registry,
    save_registry,
    load_evolution_log,
    save_evolution_log,
    schema_identity_hash,
)
from pi_interoperability_layer.execution import (
    EventRecord,
    ReplayLedger,
    ExecutionEngine,
    canonical_event_payload,
)
from pi_interoperability_layer.interfaces import (
    WorkerInputEnvelope,
    WorkerOutputEnvelope,
    RuntimeMessage,
    ProvenanceChain,
    ReplaySafeRouter,
)
from pi_interoperability_layer.blast_radius import (
    TopologyNode,
    TopologyEdge,
    TopologyGraph,
    BlastRadiusScore,
    BlastRadiusReport,
    BlastRadiusEngine,
)
from pi_interoperability_layer.cicd import (
    GitHubActionsWorkflow,
    PRGateConfig,
    PRGateResult,
    ArtifactVerificationResult,
    ReplayValidationGate,
    PolicyEnforcementHook,
)
from pi_interoperability_layer.registry import (
    SnapshotRegistry,
    SnapshotRecord,
    SnapshotMetadata,
    ReplayBundle,
    RetentionPolicy,
)
from pi_interoperability_layer.queries import (
    SemanticQueryEngine,
    SemanticQueryResult,
)
from pi_interoperability_layer.visualization import (
    render_validation_html,
    render_diff_heatmap,
    render_topology_graph,
    render_governance_dashboard,
)
from pi_interoperability_layer.capability.registry import (
    SemanticCapabilityRegistry,
    RegistryEntry,
    RegistryEntryStatus,
    RegistryFingerprints,
    TrustScore,
    TrustScoringBasis,
)
from pi_interoperability_layer.capability.graph import (
    ExtensionCompatibilityGraph,
    CompatibilityEdge,
    CompatibilityType,
    CompatibilityCheck,
    CompatibilityVerdict,
)
from pi_interoperability_layer.capability.ingestion import (
    GovernedIngestionPipeline,
    IngestionReceipt,
    IngestionStep,
    IngestionPhase,
)
from pi_interoperability_layer.capability.indexing import (
    SemanticIndexWorker,
    SemanticQueryWorker,
    IndexEntry,
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
