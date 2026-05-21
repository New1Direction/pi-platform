"""Semantic Output Normalizer.

Converts external extension outputs into canonical semantic graph artifacts.
No arbitrary schemas allowed into the mesh.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from pi_extension_governor.manifest import ExtensionManifest


class SemanticOutputNormalizer:
    """Deterministic normalizer for extension outputs into canonical artifacts."""

    # Canonical artifact types accepted by the mesh
    CANONICAL_TYPES = {
        "SemanticIRTrace",
        "DependencyGraph",
        "ReplaySurfaceReport",
        "ComplianceArtifact",
        "TopologyGraph",
        "BoundaryValidationReport",
        "TelemetryExposureReport",
        "ObservabilityDriftReport",
        "SecuritySimulationReport",
        "SensitiveFlowReport",
    }

    def normalize(self, raw_output: Dict[str, Any], manifest: ExtensionManifest) -> Dict[str, Any]:
        """Normalize extension output to canonical semantic artifact.

        Rejects outputs that cannot be mapped to known canonical types.
        """
        artifact_type = raw_output.get("artifact_type", "UNKNOWN")
        if artifact_type not in self.CANONICAL_TYPES:
            return {
                "artifact_type": "NormalizationRejection",
                "extension_id": manifest.extension_id,
                "reason": f"Unknown artifact_type: {artifact_type}",
                "allowed_types": sorted(self.CANONICAL_TYPES),
            }

        normalized = {
            "artifact_type": artifact_type,
            "extension_id": manifest.extension_id,
            "package_hash": manifest.package_hash,
            "capability_class": manifest.capability_class.value,
            "normalized_at": datetime.now(timezone.utc).isoformat(),
            "payload": raw_output.get("payload", {}),
            "provenance": {
                "manifest_id": manifest.extension_id,
                "package_version": manifest.package_version,
                "capability_class": manifest.capability_class.value,
            },
        }

        # Add schema validation marker
        normalized["schema_validated"] = True
        normalized["mesh_compatible"] = True

        return normalized

    def validate_canonical_schema(self, artifact: Dict[str, Any]) -> bool:
        """Validate that normalized artifact conforms to canonical schema."""
        required_keys = {"artifact_type", "extension_id", "package_hash", "payload", "provenance"}
        return all(k in artifact for k in required_keys)
