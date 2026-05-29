"""pi_interoperability_layer.catalog: Catalog integration layer for external packages.

Deterministic ingestion, classification, policy gating, sandbox validation,
normalization, dependency expansion, and composition planning for
external catalog packages (e.g., Notte pi-packages-catalog).

No credential storage. API keys from environment only.
No execution autonomy. Evidence-bound at every step.
"""

from pi_interoperability_layer.catalog.classifier_worker import (
    CapabilityClassificationResult,
    CapabilityClassifierWorker,
    ClassificationEvidence,
)
from pi_interoperability_layer.catalog.composition_planner import (
    CapabilityCompositionPlanner,
    CompositionNode,
    CompositionPlan,
)
from pi_interoperability_layer.catalog.dependency_expansion_worker import (
    DependencyExpansionReceipt,
    DependencyGraphExpansionWorker,
)
from pi_interoperability_layer.catalog.ingest_worker import (
    CatalogIngestReceipt,
    PackageCatalogIngestWorker,
)
from pi_interoperability_layer.catalog.normalization_worker import (
    PackageNormalizationReceipt,
    PackageNormalizationWorker,
)
from pi_interoperability_layer.catalog.notte_client import (
    CatalogPage,
    CatalogSearchResult,
    NotteCatalogClient,
)
from pi_interoperability_layer.catalog.pipeline import (
    CatalogIntegrationPipeline,
    CatalogPipelineReceipt,
)
from pi_interoperability_layer.catalog.policy_gate_worker import (
    PackagePolicyGateResult,
    PackagePolicyGateWorker,
    PolicyGateFinding,
)
from pi_interoperability_layer.catalog.sandbox_worker import (
    SandboxValidationReceipt,
    SandboxValidationWorker,
)

__all__ = [
    "CatalogPage",
    "CatalogSearchResult",
    "NotteCatalogClient",
    "CatalogIngestReceipt",
    "PackageCatalogIngestWorker",
    "CapabilityClassificationResult",
    "ClassificationEvidence",
    "CapabilityClassifierWorker",
    "PackagePolicyGateResult",
    "PolicyGateFinding",
    "PackagePolicyGateWorker",
    "SandboxValidationReceipt",
    "SandboxValidationWorker",
    "PackageNormalizationReceipt",
    "PackageNormalizationWorker",
    "DependencyExpansionReceipt",
    "DependencyGraphExpansionWorker",
    "CompositionNode",
    "CompositionPlan",
    "CapabilityCompositionPlanner",
    "CatalogPipelineReceipt",
    "CatalogIntegrationPipeline",
]
