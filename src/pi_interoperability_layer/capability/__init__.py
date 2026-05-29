"""pi_interoperability_layer.capability: Semantic capability registry and indexing.

Governed extension catalog, compatibility graph, ingestion pipeline,
semantic indexing, and distributed shard coordination.
"""

from pi_interoperability_layer.capability.graph import (
    CompatibilityCheck,
    CompatibilityEdge,
    CompatibilityType,
    CompatibilityVerdict,
    ExtensionCompatibilityGraph,
)
from pi_interoperability_layer.capability.indexing import (
    IndexEntry,
    IndexField,
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
