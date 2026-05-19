"""pi-extension-governor: Governed extension ecosystem for deterministic semantic worker mesh.

Safely ingests, normalizes, sandboxes, validates, and governs external extensions
before they are allowed into the semantic worker mesh.

No autonomy expansion. Specialization-first scaling only.
"""

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionBundle,
    ExtensionManifest,
    ExtensionStatus,
    TrustZone,
)
from pi_extension_governor.inspector import (
    CapabilityClassification,
    InspectionFinding,
    InspectionReport,
    StaticCapabilityInspector,
)
from pi_extension_governor.sandbox import (
    SandboxResult,
    SandboxedExtensionRuntime,
)
from pi_extension_governor.policy import (
    ExtensionGovernancePolicy,
    PolicyEvaluation,
    PolicyRule,
)
from pi_extension_governor.normalizer import SemanticOutputNormalizer
from pi_extension_governor.provenance import (
    ExtensionExecutionReceipt,
    ExtensionProvenanceLedger,
)
from pi_extension_governor.trust_zones import (
    TrustZoneDecision,
    TrustZoneEnforcer,
)
from pi_extension_governor.governor import (
    ExtensionAdmissionResult,
    ExtensionGovernor,
)

__version__ = "0.1.0"
__all__ = [
    "CapabilityClass",
    "ExtensionBundle",
    "ExtensionManifest",
    "ExtensionStatus",
    "TrustZone",
    "CapabilityClassification",
    "InspectionFinding",
    "InspectionReport",
    "StaticCapabilityInspector",
    "SandboxResult",
    "SandboxedExtensionRuntime",
    "ExtensionGovernancePolicy",
    "PolicyEvaluation",
    "PolicyRule",
    "SemanticOutputNormalizer",
    "ExtensionExecutionReceipt",
    "ExtensionProvenanceLedger",
    "TrustZoneDecision",
    "TrustZoneEnforcer",
    "ExtensionAdmissionResult",
    "ExtensionGovernor",
]
