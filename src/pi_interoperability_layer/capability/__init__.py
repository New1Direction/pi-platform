"""pi_interoperability_layer.capability: Semantic capability registry and indexing.

Governed extension catalog, compatibility graph, ingestion pipeline,
semantic indexing, and distributed shard coordination.
"""

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
    IndexField,
)

__all__ = [
    "SemanticCapabilityRegistry",
    "RegistryEntry",
    "RegistryEntryStatus",
    "RegistryFingerprints",
    "TrustScore",
    "TrustScoringBasis",
    "ExtensionCompatibilityGraph",
    "CompatibilityEdge",
    "CompatibilityType",
    "CompatibilityCheck",
    "CompatibilityVerdict",
    "GovernedIngestionPipeline",
    "IngestionReceipt",
    "IngestionStep",
    "IngestionPhase",
    "SemanticIndexWorker",
    "SemanticQueryWorker",
    "IndexEntry",
    "IndexField",
]