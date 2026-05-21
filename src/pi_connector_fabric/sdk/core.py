"""Governed Connector Fabric — SDK.

Deterministic connector primitives for ingestion, normalization, and semantic
compilation of real-world infrastructure telemetry.

All connector workers are read-only by default. Mutation is gated by governance.
All outputs are immutable typed artifacts with provenance receipts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Tuple

# ──────────────────────────────
#  Ingestion Contracts
# ──────────────────────────────

class ConnectorCapabilityClass(str, Enum):
    """Classification of connector capabilities."""
    TOPOLOGY_READ = "topology:read"
    IDENTITY_READ = "identity:read"
    DEPENDENCY_READ = "dependency:read"
    TRACE_READ = "trace:read"
    EVENT_READ = "event:read"
    STATE_READ = "state:read"
    LINEAGE_READ = "lineage:read"
    SECURITY_READ = "security:read"
    METRIC_READ = "metric:read"
    LOG_READ = "log:read"


class ConnectorSandboxPolicy(str, Enum):
    """Sandbox isolation level for connector execution."""
    READ_ONLY = "read_only"
    READ_WITH_CACHE = "read_with_cache"
    READ_WITH_STREAM = "read_with_stream"
    ADMITTED_MUTATION = "admitted_mutation"  # requires governance approval


class ConnectorExecutionFence(Enum):
    """Deterministic fence for connector execution boundaries."""
    NO_EXECUTION = auto()
    SANDBOXED_READ = auto()
    GOVERNANCE_APPROVED = auto()
    TIMEBOXED_LEASE = auto()


@dataclass(frozen=True)
class ConnectorManifest:
    """Deterministic connector manifest.

    Every connector is identified by a SHA-256 fingerprint of this manifest.
    All fields participate in hash computation.
    """

    connector_id: str
    name: str
    version: str
    description: str
    capability_classes: Tuple[ConnectorCapabilityClass, ...]
    sandbox_policy: ConnectorSandboxPolicy
    target_systems: Tuple[str, ...]
    output_schemas: Tuple[str, ...]
    required_credentials: Tuple[str, ...]
    config_schema: Dict[str, Any]
    author_verified: bool = False
    trust_tier: str = "unverified"
    manifest_hash: str = ""

    def __post_init__(self) -> None:
        if not self.manifest_hash:
            canonical = {
                "connector_id": self.connector_id,
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "capability_classes": sorted([c.value for c in self.capability_classes]),
                "sandbox_policy": self.sandbox_policy.value,
                "target_systems": sorted(self.target_systems),
                "output_schemas": sorted(self.output_schemas),
                "required_credentials": sorted(self.required_credentials),
                "config_schema": json.dumps(self.config_schema, sort_keys=True, separators=(",", ":")),
                "author_verified": self.author_verified,
                "trust_tier": self.trust_tier,
            }
            h = hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            object.__setattr__(self, "manifest_hash", h)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capability_classes": [c.value for c in self.capability_classes],
            "sandbox_policy": self.sandbox_policy.value,
            "target_systems": list(self.target_systems),
            "output_schemas": list(self.output_schemas),
            "required_credentials": list(self.required_credentials),
            "config_schema": self.config_schema,
            "author_verified": self.author_verified,
            "trust_tier": self.trust_tier,
            "manifest_hash": self.manifest_hash,
        }


@dataclass(frozen=True)
class IngestionReceipt:
    """Deterministic receipt for every connector ingestion run."""

    receipt_id: str
    connector_id: str
    connector_version: str
    tenant_id: str
    actor_id: str
    correlation_id: str
    ingestion_start: str
    ingestion_end: str
    artifact_count: int
    artifact_hashes: Tuple[str, ...]
    fence_used: ConnectorExecutionFence
    sandbox_policy: ConnectorSandboxPolicy
    error_count: int
    errors: Tuple[str, ...]
    receipt_hash: str = ""

    def __post_init__(self) -> None:
        if not self.receipt_hash:
            canonical = {
                "receipt_id": self.receipt_id,
                "connector_id": self.connector_id,
                "connector_version": self.connector_version,
                "tenant_id": self.tenant_id,
                "artifact_count": self.artifact_count,
                "artifact_hashes": sorted(self.artifact_hashes),
                "fence_used": self.fence_used.name,
                "error_count": self.error_count,
                "errors": list(self.errors),
                "ingestion_start": self.ingestion_start,
                "ingestion_end": self.ingestion_end,
            }
            h = hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            object.__setattr__(self, "receipt_hash", h)

    def verify(self) -> bool:
        """Deterministic receipt verification."""
        fresh = IngestionReceipt(
            receipt_id=self.receipt_id,
            connector_id=self.connector_id,
            connector_version=self.connector_version,
            tenant_id=self.tenant_id,
            actor_id=self.actor_id,
            correlation_id=self.correlation_id,
            ingestion_start=self.ingestion_start,
            ingestion_end=self.ingestion_end,
            artifact_count=self.artifact_count,
            artifact_hashes=self.artifact_hashes,
            fence_used=self.fence_used,
            sandbox_policy=self.sandbox_policy,
            error_count=self.error_count,
            errors=self.errors,
        )
        return fresh.receipt_hash == self.receipt_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "connector_id": self.connector_id,
            "connector_version": self.connector_version,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "correlation_id": self.correlation_id,
            "ingestion_start": self.ingestion_start,
            "ingestion_end": self.ingestion_end,
            "artifact_count": self.artifact_count,
            "artifact_hashes": list(self.artifact_hashes),
            "fence_used": self.fence_used.name,
            "sandbox_policy": self.sandbox_policy.value,
            "error_count": self.error_count,
            "errors": list(self.errors),
            "receipt_hash": self.receipt_hash,
        }


# ──────────────────────────────
#  Artifact Normalizer
# ──────────────────────────────

class NormalizationError(Exception):
    """Raised when external data cannot be normalized into canonical artifact."""


@dataclass(frozen=True)
class NormalizedArtifact:
    """Canonical normalized artifact output from any connector."""

    artifact_id: str
    artifact_family: str
    artifact_schema_version: str
    source_system: str
    connector_id: str
    connector_version: str
    tenant_id: str
    correlation_id: str
    created_at: str
    payload: Dict[str, Any]
    provenance: Tuple[Dict[str, Any], ...]
    artifact_hash: str = ""

    def __post_init__(self) -> None:
        if not self.artifact_hash:
            canonical = {
                "artifact_id": self.artifact_id,
                "artifact_family": self.artifact_family,
                "artifact_schema_version": self.artifact_schema_version,
                "source_system": self.source_system,
                "connector_id": self.connector_id,
                "connector_version": self.connector_version,
                "tenant_id": self.tenant_id,
                "payload": json.dumps(self.payload, sort_keys=True, separators=(",", ":"), default=str),
                "provenance": [json.dumps(p, sort_keys=True, separators=(",", ":"), default=str) for p in self.provenance],
            }
            h = hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()
            ).hexdigest()
            object.__setattr__(self, "artifact_hash", h)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_family": self.artifact_family,
            "artifact_schema_version": self.artifact_schema_version,
            "source_system": self.source_system,
            "connector_id": self.connector_id,
            "connector_version": self.connector_version,
            "tenant_id": self.tenant_id,
            "correlation_id": self.correlation_id,
            "created_at": self.created_at,
            "payload": self.payload,
            "provenance": list(self.provenance),
            "artifact_hash": self.artifact_hash,
        }


class ArtifactNormalizer:
    """Deterministic normalizer for external infrastructure data.

    Converts raw telemetry into canonical NormalizedArtifact instances.
    Enforces deterministic encoding, stable hashing, and schema fingerprinting.
    """

    _patterns: Dict[str, re.Pattern] = {}

    @classmethod
    def _slugify(cls, value: str) -> str:
        """Deterministic slug generation from any string."""
        normalized = value.lower().strip()
        normalized = re.sub(r"[^a-z0-9_]+", "_", normalized)
        return re.sub(r"_+", "_", normalized).strip("_")[:128]

    @classmethod
    def canonicalize_id(cls, system: str, namespace: str, name: str, tenant: str) -> str:
        """Generate deterministic canonical artifact ID."""
        base = f"{tenant}/{system}/{namespace}/{name}"
        return hashlib.sha256(base.encode()).hexdigest()[:32]

    @classmethod
    def normalize_topology(
        cls,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize raw topology data into canonical TopologyArtifact."""
        canonical_nodes = cls._canonicalize_list(nodes, key="id")
        canonical_edges = cls._canonicalize_list(edges, key="from")

        payload = {
            "node_count": len(canonical_nodes),
            "edge_count": len(canonical_edges),
            "nodes": canonical_nodes,
            "edges": canonical_edges,
        }

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "topology", correlation_id, tenant_id),
            artifact_family="TopologyArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            provenance=(
                {"step": "ingestion", "source": source_system, "connector": connector_id},
                {"step": "normalization", "nodes_raw": len(nodes), "edges_raw": len(edges)},
            ),
        )

    @classmethod
    def normalize_identity_graph(
        cls,
        identities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize identity data into IdentityGraphArtifact."""
        canonical_identities = cls._canonicalize_list(identities, key="arn")
        canonical_relationships = cls._canonicalize_list(relationships, key="from")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "identity", correlation_id, tenant_id),
            artifact_family="IdentityGraphArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "identity_count": len(canonical_identities),
                "relationship_count": len(canonical_relationships),
                "identities": canonical_identities,
                "relationships": canonical_relationships,
            },
            provenance=(
                {"step": "ingestion", "source": source_system},
                {"step": "normalization"},
            ),
        )

    @classmethod
    def normalize_dependency_graph(
        cls,
        dependencies: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize dependency mapping into DependencyGraphArtifact."""
        canonical_deps = cls._canonicalize_list(dependencies, key="from")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "dependency", correlation_id, tenant_id),
            artifact_family="DependencyGraphArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "dependency_count": len(canonical_deps),
                "dependencies": canonical_deps,
            },
            provenance=({"step": "ingestion"}, {"step": "normalization"}),
        )

    @classmethod
    def normalize_trace_topology(
        cls,
        spans: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize trace spans into TraceTopologyArtifact."""
        canonical_spans = cls._canonicalize_list(spans, key="span_id")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "trace", correlation_id, tenant_id),
            artifact_family="TraceTopologyArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "span_count": len(canonical_spans),
                "spans": canonical_spans,
            },
            provenance=({"step": "ingestion"}, {"step": "normalization"}),
        )

    @classmethod
    def normalize_infrastructure_state(
        cls,
        resources: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize infrastructure state into InfrastructureStateArtifact."""
        canonical_resources = cls._canonicalize_list(resources, key="id")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "state", correlation_id, tenant_id),
            artifact_family="InfrastructureStateArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "resource_count": len(canonical_resources),
                "resources": canonical_resources,
            },
            provenance=({"step": "ingestion"}, {"step": "normalization"}),
        )

    @classmethod
    def normalize_deployment_lineage(
        cls,
        deployments: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize deployment data into DeploymentLineageArtifact."""
        canonical_deployments = cls._canonicalize_list(deployments, key="id")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "lineage", correlation_id, tenant_id),
            artifact_family="DeploymentLineageArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "deployment_count": len(canonical_deployments),
                "deployments": canonical_deployments,
            },
            provenance=({"step": "ingestion"}, {"step": "normalization"}),
        )

    @classmethod
    def normalize_security_event(
        cls,
        events: List[Dict[str, Any]],
        source_system: str,
        connector_id: str,
        connector_version: str,
        tenant_id: str,
        correlation_id: str,
    ) -> NormalizedArtifact:
        """Normalize security events into SecurityEventArtifact."""
        canonical_events = cls._canonicalize_list(events, key="event_id")

        return NormalizedArtifact(
            artifact_id=cls.canonicalize_id(source_system, "security", correlation_id, tenant_id),
            artifact_family="SecurityEventArtifact",
            artifact_schema_version="1.0.0",
            source_system=source_system,
            connector_id=connector_id,
            connector_version=connector_version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            payload={
                "event_count": len(canonical_events),
                "events": canonical_events,
            },
            provenance=({"step": "ingestion"}, {"step": "normalization"}),
        )

    @classmethod
    def _canonicalize_list(
        cls, items: List[Dict[str, Any]], key: str
    ) -> List[Dict[str, Any]]:
        """Deterministically canonicalize a list of dicts by sorting."""
        def sort_key(item: Dict[str, Any]) -> str:
            v = item.get(key, "")
            return str(v) if v is not None else ""
        sorted_items = sorted(items, key=sort_key)
        return [json.loads(json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)) for item in sorted_items]


# ──────────────────────────────
#  Base Connector Worker
# ──────────────────────────────

class BaseConnectorWorker:
    """Abstract base for all deterministic ingestion connectors.

    Subclass must implement `ingest()` only. No external mutation allowed
    unless governance-approved fence is acquired.
    """

    def __init__(self, manifest: ConnectorManifest, config: Dict[str, Any]) -> None:
        self.manifest = manifest
        self.config = config
        self._normalizer = ArtifactNormalizer()

    def ingest(
        self,
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
    ) -> Tuple[List[NormalizedArtifact], IngestionReceipt]:
        """Execute ingestion run. Must be implemented by subclass.

        All ingestion is read-only by default. Any attempt to mutate external
        systems without governance approval raises ConnectorExecutionFence.
        """
        raise NotImplementedError("Subclass must implement ingest()")

    def _produce_receipt(
        self,
        artifacts: List[NormalizedArtifact],
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
        start_time: str,
        errors: List[str],
    ) -> IngestionReceipt:
        """Produce deterministic ingestion receipt."""
        return IngestionReceipt(
            receipt_id=f"rcpt_{correlation_id}_{self.manifest.connector_id}",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            ingestion_start=start_time,
            ingestion_end=datetime.now(timezone.utc).isoformat(),
            artifact_count=len(artifacts),
            artifact_hashes=tuple(a.artifact_hash for a in artifacts),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=self.manifest.sandbox_policy,
            error_count=len(errors),
            errors=tuple(errors),
        )

    def _require_read_only(self) -> None:
        """Enforce read-only fence. Raises if mutation detected."""
        if self.manifest.sandbox_policy != ConnectorSandboxPolicy.READ_ONLY:
            if self.manifest.sandbox_policy == ConnectorSandboxPolicy.ADMITTED_MUTATION:
                raise PermissionError(
                    f"Connector {self.manifest.connector_id} requires governance approval for mutation"
                )


def register_connector(
    connector_class: type,
    manifest: ConnectorManifest,
    registry: Dict[str, Dict[str, Any]],
) -> Tuple[bool, str]:
    """Register a connector in the marketplace registry.

    Returns (success, message).
    """
    if manifest.connector_id in registry:
        return False, f"Connector {manifest.connector_id} already registered"
    registry[manifest.connector_id] = {
        "manifest": manifest.to_dict(),
        "class": connector_class.__name__,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "trust_tier": manifest.trust_tier,
    }
    return True, f"Registered {manifest.connector_id} ({manifest.manifest_hash[:16]})"
