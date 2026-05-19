"""Capability Economy Layer — Deterministic Capability Marketplace.

A governed, schema-driven package manager for executable capability graphs.
NOT a recommendation system. NOT an AI planner.
Deterministic discovery, composition, and lifecycle management only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, ValidationError

from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest, ExtensionStatus, TrustZone


# ── Capability Lifecycle States ──────────────────────────────────

class CapabilityLifecycleState(str, Enum):
    PUBLISHED = "published"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    ADMITTED = "admitted"
    AVAILABLE = "available"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class TrustTier(str, Enum):
    UNTRUSTED = "untrusted"
    BASIC = "basic"
    VERIFIED = "verified"
    CERTIFIED = "certified"
    CORE = "core"


# ── Composition Request Schema ───────────────────────────────────

class CompositionNode(BaseModel):
    """Explicit node definition for a capability composition request.

    No natural language. No inference. Every field is explicit.
    """

    node_id: str
    manifest_id: str
    capability_class: CapabilityClass
    required_inputs: List[str] = Field(default_factory=list)
    expected_outputs: List[str] = Field(default_factory=list)
    trust_tier_minimum: TrustTier = TrustTier.BASIC
    parameters: Dict[str, Any] = Field(default_factory=dict)


class CompositionEdge(BaseModel):
    """Explicit edge definition for a capability composition request."""

    source_node_id: str
    target_node_id: str
    edge_type: str = "depends_on"  # depends_on, requires_capability, compatible_with
    required: bool = True


class CompositionRequest(BaseModel):
    """Schema-driven composition request.

    This is the ONLY way to request a capability graph.
    No natural language input is accepted.
    Must validate against this schema.
    """

    request_id: str
    tenant_id: str
    description: str
    nodes: List[CompositionNode]
    edges: List[CompositionEdge]
    max_depth: int = 5
    max_nodes: int = 50
    fail_on_conflict: bool = True
    deterministic_only: bool = True
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = self.model_dump()
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


# ── Market Capability Listing ────────────────────────────────────

@dataclass(frozen=True)
class MarketCapabilityListing:
    """A capability available in the marketplace."""

    listing_id: str
    manifest_id: str
    name: str
    version: str
    capability_class: CapabilityClass
    trust_tier: TrustTier
    trust_score: int = 0
    lifecycle_state: CapabilityLifecycleState = CapabilityLifecycleState.PUBLISHED
    dependencies: Tuple[str, ...] = field(default_factory=tuple)
    published_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    review_receipt_hash: str = ""
    last_verified_at: str = ""
    deprecation_reason: str = ""
    publisher_tenant_id: str = ""

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "listing_id": self.listing_id,
                "manifest_id": self.manifest_id,
                "name": self.name,
                "version": self.version,
                "capability_class": self.capability_class.value,
                "trust_tier": self.trust_tier.value,
                "trust_score": self.trust_score,
                "lifecycle_state": self.lifecycle_state.value,
                "dependencies": sorted(self.dependencies),
                "review_receipt_hash": self.review_receipt_hash,
                "publisher_tenant_id": self.publisher_tenant_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


# ── Deterministic Composition Engine ─────────────────────────────

@dataclass(frozen=True)
class CompositionResult:
    """Result of deterministic composition.

    Contains the resolved graph or a rejection reason.
    No inference. No probabilistic matching.
    """

    request_id: str
    valid: bool
    resolved_manifests: Tuple[ExtensionManifest, ...]
    resolved_edges: Tuple[CompositionEdge, ...]
    missing_dependencies: Tuple[str, ...]
    conflict_evidence: Tuple[str, ...]
    composition_hash: str = ""
    rejection_reason: str = ""
    phase_count: int = 0

    def compute_hash(self) -> str:
        # Use only deterministic fields — avoid timestamps in manifests
        data = json.dumps(
            {
                "request_id": self.request_id,
                "valid": self.valid,
                "resolved_manifests": sorted([m.extension_id for m in self.resolved_manifests]),
                "resolved_edges": sorted(
                    [f"{e.source_node_id}→{e.target_node_id}:{e.edge_type}" for e in self.resolved_edges]
                ),
                "missing_dependencies": sorted(self.missing_dependencies),
                "conflict_evidence": list(self.conflict_evidence),
                "rejection_reason": self.rejection_reason,
                "phase_count": self.phase_count,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(data.encode()).hexdigest()


class CompositionEngine:
    """Deterministic capability composition engine.

    Resolves explicit composition requests into validated capability graphs.
    No recommendation logic. No probabilistic matching.
    Strictly: validate → resolve → verify → output.
    """

    def __init__(self, catalog: Dict[str, MarketCapabilityListing] = None) -> None:
        self.catalog: Dict[str, MarketCapabilityListing] = catalog or {}
        self.composition_history: List[CompositionResult] = []

    def register_listing(self, listing: MarketCapabilityListing) -> None:
        self.catalog[listing.listing_id] = listing

    def compose(self, request: CompositionRequest) -> CompositionResult:
        """Execute deterministic composition from explicit request.

        Steps:
        1. Validate request schema
        2. Resolve each node to a manifest from catalog
        3. Check trust tier requirements
        4. Resolve edges
        5. Detect conflicts
        6. Topological phase assignment
        7. Return resolved graph or rejection
        """
        # 1. Validate request
        validation_errors = self._validate_request(request)
        if validation_errors:
            return self._reject(request, f"Validation failed: {'; '.join(validation_errors)}")

        # 2. Resolve nodes
        resolved_manifests: List[ExtensionManifest] = []
        missing_deps: List[str] = []
        conflict_evidence: List[str] = []

        for node in request.nodes:
            found = self._resolve_node(node)
            if found is None:
                if node.node_id in {e.target_node_id for e in request.edges}:
                    missing_deps.append(node.node_id)
                else:
                    return self._reject(request, f"Node not found in catalog: {node.node_id} (manifest_id={node.manifest_id})")
                continue

            # 3. Check trust tier
            listing = next(
                (l for l in self.catalog.values() if l.manifest_id == node.manifest_id),
                None,
            )
            if listing and not self._trust_tier_satisfies(listing.trust_tier, node.trust_tier_minimum):
                conflict_evidence.append(
                    f"Trust tier mismatch for {node.node_id}: "
                    f"available={listing.trust_tier.value}, required={node.trust_tier_minimum.value}"
                )
                if request.fail_on_conflict:
                    return self._reject(request, conflict_evidence[-1])

            resolved_manifests.append(found)

        # Enforce max_nodes
        if len(resolved_manifests) > request.max_nodes:
            return self._reject(request, f"Node count {len(resolved_manifests)} exceeds max {request.max_nodes}")

        # 5. Detect edge conflicts
        for edge in request.edges:
            if edge.required:
                if edge.source_node_id not in {n.node_id for n in request.nodes}:
                    conflict_evidence.append(f"Required edge source not in request: {edge.source_node_id}")
                if edge.target_node_id not in {n.node_id for n in request.nodes}:
                    conflict_evidence.append(f"Required edge target not in request: {edge.target_node_id}")

        if conflict_evidence and request.fail_on_conflict:
            return self._reject(request, f"Conflicts detected: {'; '.join(conflict_evidence)}")

        # 6. Simple phase assignment (topological)
        in_degree: Dict[str, int] = {n.node_id: 0 for n in request.nodes}
        adj: Dict[str, List[str]] = {n.node_id: [] for n in request.nodes}
        for edge in request.edges:
            if edge.edge_type == "depends_on" and edge.source_node_id in in_degree:
                in_degree[edge.target_node_id] = in_degree.get(edge.target_node_id, 0) + 1
                adj.setdefault(edge.source_node_id, []).append(edge.target_node_id)

        # Kahn's algorithm for topological phases
        phases = 0
        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        visited = set()
        while queue:
            phases += 1
            if phases > request.max_depth:
                return self._reject(request, f"Exceeds max depth {request.max_depth}")
            next_queue = []
            for nid in queue:
                visited.add(nid)
                for neighbor in adj.get(nid, []):
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0 and neighbor not in visited:
                        next_queue.append(neighbor)
            queue = next_queue

        result = CompositionResult(
            request_id=request.request_id,
            valid=True,
            resolved_manifests=tuple(resolved_manifests),
            resolved_edges=tuple(request.edges),
            missing_dependencies=tuple(missing_deps),
            conflict_evidence=tuple(conflict_evidence),
            rejection_reason="",
            phase_count=phases,
        )
        final_result = self._with_computed_hash(result)
        self.composition_history.append(final_result)
        return final_result

    # ── Internal helpers ─────────────────────────────────────────

    def _validate_request(self, request: CompositionRequest) -> List[str]:
        errors: List[str] = []
        if not request.nodes:
            errors.append("At least one node required")
        if len(request.nodes) > request.max_nodes:
            errors.append(f"Nodes {len(request.nodes)} > max_nodes {request.max_nodes}")
        # Check for duplicate node IDs
        seen = set()
        for node in request.nodes:
            if node.node_id in seen:
                errors.append(f"Duplicate node_id: {node.node_id}")
            seen.add(node.node_id)
        # Validate edge references
        node_ids = {n.node_id for n in request.nodes}
        for edge in request.edges:
            if edge.source_node_id not in node_ids:
                errors.append(f"Edge references unknown source: {edge.source_node_id}")
            if edge.target_node_id not in node_ids:
                errors.append(f"Edge references unknown target: {edge.target_node_id}")
        return errors

    def _resolve_node(self, node: CompositionNode) -> Optional[ExtensionManifest]:
        # Search catalog by manifest_id
        for listing in self.catalog.values():
            if listing.manifest_id == node.manifest_id:
                # Map trust tier to trust zone
                tier_to_zone = {
                    TrustTier.UNTRUSTED: TrustZone.SANDBOX_EXPERIMENTAL,
                    TrustTier.BASIC: TrustZone.SANDBOX_EXPERIMENTAL,
                    TrustTier.VERIFIED: TrustZone.GOVERNED_EXTENSION,
                    TrustTier.CERTIFIED: TrustZone.GOVERNED_EXTENSION,
                    TrustTier.CORE: TrustZone.CORE_TRUSTED,
                }
                return ExtensionManifest(
                    extension_id=listing.manifest_id,
                    package_name=listing.name,
                    package_version=listing.version,
                    package_hash=listing.compute_hash(),
                    capability_class=listing.capability_class,
                    trust_zone=tier_to_zone.get(listing.trust_tier, TrustZone.SANDBOX_EXPERIMENTAL),
                    status=ExtensionStatus.ADMITTED,
                )
        return None

    def _trust_tier_satisfies(self, available: TrustTier, minimum: TrustTier) -> bool:
        """Check if available trust tier meets minimum requirement."""
        tier_order = [TrustTier.UNTRUSTED, TrustTier.BASIC, TrustTier.VERIFIED, TrustTier.CERTIFIED, TrustTier.CORE]
        if available not in tier_order or minimum not in tier_order:
            return False
        return tier_order.index(available) >= tier_order.index(minimum)

    def _reject(self, request: CompositionRequest, reason: str) -> CompositionResult:
        result = CompositionResult(
            request_id=request.request_id,
            valid=False,
            resolved_manifests=(),
            resolved_edges=(),
            missing_dependencies=(),
            conflict_evidence=(),
            rejection_reason=reason,
        )
        final_result = self._with_computed_hash(result)
        self.composition_history.append(final_result)
        return final_result

    @staticmethod
    def _with_computed_hash(result: CompositionResult) -> CompositionResult:
        # We need a new frozen instance with the hash field set
        return CompositionResult(
            request_id=result.request_id,
            valid=result.valid,
            resolved_manifests=result.resolved_manifests,
            resolved_edges=result.resolved_edges,
            missing_dependencies=result.missing_dependencies,
            conflict_evidence=result.conflict_evidence,
            composition_hash=result.compute_hash(),
            rejection_reason=result.rejection_reason,
            phase_count=result.phase_count,
        )


# ── Capability Marketplace Registry ──────────────────────────────

class CapabilityMarketplaceRegistry:
    """Deterministic marketplace registry for capability listings.

    Manages lifecycle states and trust scoring.
    No probabilistic ranking. Evidence-based only.
    """

    def __init__(self) -> None:
        self._listings: Dict[str, MarketCapabilityListing] = {}
        self._lifecycle_events: List[Dict[str, Any]] = []

    def publish(self, listing: MarketCapabilityListing) -> None:
        self._listings[listing.listing_id] = listing
        self._log_event(listing, "PUBLISH")

    def transition_state(
        self,
        listing_id: str,
        new_state: CapabilityLifecycleState,
        reason: str = "",
        evidence_hash: str = "",
    ) -> bool:
        listing = self._listings.get(listing_id)
        if not listing:
            return False
        updated = MarketCapabilityListing(
            listing_id=listing.listing_id,
            manifest_id=listing.manifest_id,
            name=listing.name,
            version=listing.version,
            capability_class=listing.capability_class,
            trust_tier=listing.trust_tier,
            trust_score=listing.trust_score,
            lifecycle_state=new_state,
            dependencies=listing.dependencies,
            published_at=listing.published_at,
            review_receipt_hash=listing.review_receipt_hash,
            last_verified_at=listing.last_verified_at,
            deprecation_reason=reason if new_state == CapabilityLifecycleState.DEPRECATED else listing.deprecation_reason,
            publisher_tenant_id=listing.publisher_tenant_id,
        )
        self._listings[listing_id] = updated
        self._log_event(updated, f"TRANSITION→{new_state.value}", evidence_hash)
        return True

    def update_trust_score(self, listing_id: str, new_score: int, evidence: str = "") -> bool:
        listing = self._listings.get(listing_id)
        if not listing:
            return False
        updated = MarketCapabilityListing(
            listing_id=listing.listing_id,
            manifest_id=listing.manifest_id,
            name=listing.name,
            version=listing.version,
            capability_class=listing.capability_class,
            trust_tier=listing.trust_tier,
            trust_score=new_score,
            lifecycle_state=listing.lifecycle_state,
            dependencies=listing.dependencies,
            published_at=listing.published_at,
            review_receipt_hash=listing.review_receipt_hash,
            last_verified_at=datetime.now(timezone.utc).isoformat(),
            deprecation_reason=listing.deprecation_reason,
            publisher_tenant_id=listing.publisher_tenant_id,
        )
        self._listings[listing_id] = updated
        self._log_event(updated, "TRUST_SCORE_UPDATE", evidence)
        return True

    def get_listing(self, listing_id: str) -> Optional[MarketCapabilityListing]:
        return self._listings.get(listing_id)

    def query_by_class(self, cap_class: CapabilityClass) -> Tuple[MarketCapabilityListing, ...]:
        return tuple(l for l in self._listings.values() if l.capability_class == cap_class)

    def query_by_tier(self, tier: TrustTier) -> Tuple[MarketCapabilityListing, ...]:
        return tuple(l for l in self._listings.values() if l.trust_tier == tier)

    def _log_event(self, listing: MarketCapabilityListing, event: str, evidence: str = "") -> None:
        self._lifecycle_events.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "listing_id": listing.listing_id,
                "manifest_id": listing.manifest_id,
                "event": event,
                "lifecycle_state": listing.lifecycle_state.value,
                "trust_score": listing.trust_score,
                "evidence": evidence,
                "listing_hash": listing.compute_hash(),
            }
        )
