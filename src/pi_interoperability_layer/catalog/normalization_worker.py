"""Package Normalization Worker.

Converts external catalog package outputs into canonical semantic graph artifacts.
Deterministic. Schema-bound. No arbitrary schemas allowed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.manifest import ExtensionManifest
from pi_extension_governor.normalizer import SemanticOutputNormalizer


@dataclass(frozen=True)
class PackageNormalizationReceipt:
    manifest_id: str
    artifact_type: str
    artifact_hash: str
    normalized: bool
    rejection_reason: Optional[str]
    receipt_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "manifest_id": self.manifest_id,
                "artifact_type": self.artifact_type,
                "artifact_hash": self.artifact_hash,
                "normalized": self.normalized,
                "rejection": self.rejection_reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def _with_computed_hash(self) -> PackageNormalizationReceipt:
        return PackageNormalizationReceipt(
            manifest_id=self.manifest_id,
            artifact_type=self.artifact_type,
            artifact_hash=self.artifact_hash,
            normalized=self.normalized,
            rejection_reason=self.rejection_reason,
            receipt_hash=self.compute_hash(),
        )


class PackageNormalizationWorker:
    """Deterministic normalization of catalog package outputs.

    Uses existing SemanticOutputNormalizer for canonical artifact types.
    Wraps with manifest-linked provenance.
    """

    def __init__(self, normalizer: Optional[SemanticOutputNormalizer] = None) -> None:
        self.normalizer = normalizer or SemanticOutputNormalizer()

    def normalize(
        self,
        manifest: ExtensionManifest,
        raw_output: Dict[str, Any],
    ) -> PackageNormalizationReceipt:
        """Normalize a package's raw output into a canonical artifact.

        Returns a receipt with artifact hash and normalization status.
        """
        try:
            artifact_type = raw_output.get("artifact_type", "")
            if not artifact_type:
                # Infer from manifest capability class
                artifact_type = self._infer_artifact_type(manifest)
                raw_output["artifact_type"] = artifact_type

            normalized = self.normalizer.normalize(raw_output, manifest)
            if normalized.get("artifact_type") == "NormalizationRejection":
                return PackageNormalizationReceipt(
                    manifest_id=manifest.extension_id,
                    artifact_type=artifact_type,
                    artifact_hash="",
                    normalized=False,
                    rejection_reason=normalized.get("reason", "Unknown artifact type"),
                    receipt_hash="",
                )._with_computed_hash()

            if self.normalizer.validate_canonical_schema(normalized):
                artifact_hash = hashlib.sha256(
                    json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                return PackageNormalizationReceipt(
                    manifest_id=manifest.extension_id,
                    artifact_type=artifact_type,
                    artifact_hash=artifact_hash,
                    normalized=True,
                    rejection_reason=None,
                    receipt_hash="",
                )._with_computed_hash()
            else:
                return PackageNormalizationReceipt(
                    manifest_id=manifest.extension_id,
                    artifact_type=artifact_type,
                    artifact_hash="",
                    normalized=False,
                    rejection_reason="Schema validation failed",
                    receipt_hash="",
                )._with_computed_hash()
        except Exception as e:
            return PackageNormalizationReceipt(
                manifest_id=manifest.extension_id,
                artifact_type="",
                artifact_hash="",
                normalized=False,
                rejection_reason=str(e),
                receipt_hash="",
            )._with_computed_hash()

    @staticmethod
    def _infer_artifact_type(manifest: ExtensionManifest) -> str:
        mapping = {
            "openapi_tooling": "SemanticIRTrace",
            "graphql_tooling": "SemanticIRTrace",
            "kubernetes_manifest": "TopologyGraph",
            "terraform_analysis": "ComplianceArtifact",
            "cicd_integration": "ReplaySurfaceReport",
            "visualization": "SemanticIRTrace",
            "observability_adapter": "TelemetryExposureReport",
            "static_analyzer": "BoundaryValidationReport",
        }
        return mapping.get(manifest.capability_class.value, "SemanticIRTrace")
