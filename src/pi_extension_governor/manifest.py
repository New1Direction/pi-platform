"""Extension Manifest System.

Deterministic manifest schema for external packages entering the semantic worker mesh.
Immutable, hash-verified, schema-bound.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CapabilityClass(str, Enum):
    OPENAPI_TOOLING = "openapi_tooling"
    GRAPHQL_TOOLING = "graphql_tooling"
    KUBERNETES_MANIFEST = "kubernetes_manifest"
    TERRAFORM_ANALYSIS = "terraform_analysis"
    CICD_INTEGRATION = "cicd_integration"
    VISUALIZATION = "visualization"
    OBSERVABILITY_ADAPTER = "observability_adapter"
    STATIC_ANALYZER = "static_analyzer"


class TrustZone(str, Enum):
    CORE_TRUSTED = "core_trusted"
    GOVERNED_EXTENSION = "governed_extension"
    SANDBOX_EXPERIMENTAL = "sandbox_experimental"


class ExtensionStatus(str, Enum):
    PENDING_INSPECTION = "pending_inspection"
    STATIC_ANALYZED = "static_analyzed"
    DETERMINISM_VERIFIED = "determinism_verified"
    SEMANTIC_NORMALIZED = "semantic_normalized"
    POLICY_APPROVED = "policy_approved"
    ADMITTED = "admitted"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class ExtensionManifest(BaseModel):
    """Immutable extension manifest. Every field is required for governance."""

    extension_id: str
    package_name: str
    package_version: str
    package_hash: str = ""  # SHA-256 of package archive
    capability_class: CapabilityClass
    declared_inputs: List[str] = Field(default_factory=list)
    declared_outputs: List[str] = Field(default_factory=list)
    network_access: bool = False
    filesystem_access: bool = False
    subprocess_access: bool = False
    dynamic_eval_access: bool = False
    thread_spawn_access: bool = False
    deterministic_claim: bool = False
    replayability_claim: bool = False
    resource_cpu_ms_max: int = 1000
    resource_memory_mb_max: int = 128
    resource_output_size_max: int = 1024 * 1024  # 1MB
    semantic_version: str = "1.0.0"
    provenance_source_url: Optional[str] = None
    provenance_author_pgp_fingerprint: Optional[str] = None
    provenance_build_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trust_zone: TrustZone = TrustZone.SANDBOX_EXPERIMENTAL
    status: ExtensionStatus = ExtensionStatus.PENDING_INSPECTION
    inspection_receipt_hash: Optional[str] = None
    normalization_receipt_hash: Optional[str] = None
    admission_receipt_hash: Optional[str] = None
    rejection_reason: Optional[str] = None
    # Catalog integration fields (optional backward-compatible additions)
    description: Optional[str] = None
    entrypoint: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    telemetry_surfaces: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        """Deterministic, content-addressed manifest hash.

        Excludes mutable receipt fields AND wall-clock provenance metadata
        (provenance_build_timestamp defaults to datetime.now), so the same
        logical manifest reproduces the same hash across constructions/runs.
        The timestamp is still stored/returned as metadata; it is only kept
        out of the hashed input.
        """
        payload = self.model_dump(
            exclude={
                "inspection_receipt_hash",
                "normalization_receipt_hash",
                "admission_receipt_hash",
                "rejection_reason",
                "status",
                "provenance_build_timestamp",
            }
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class CapabilityDeclaration(BaseModel):
    """Declared capability with bounded interface contract."""

    capability_name: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    deterministic: bool
    replay_safe: bool
    max_execution_ms: int
    model_config = {"frozen": True}


class ExtensionBundle(BaseModel):
    """Package bundle with manifest and payload hash."""

    bundle_id: str
    manifest: ExtensionManifest
    payload_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_bundle_hash(self) -> str:
        """Deterministic, content-addressed bundle hash.

        Excludes the wall-clock ``created_at`` metadata (defaults to
        datetime.now) so the same logical bundle reproduces the same hash.
        ``created_at`` remains stored/returned as metadata.
        """
        data = {
            "bundle_id": self.bundle_id,
            "manifest_hash": self.manifest.compute_hash(),
            "payload_hash": self.payload_hash,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
