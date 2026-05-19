"""Architecture Policy Schema and Loader.

The policy file is the ONLY source of governance rules.
The validator does not infer rules. It loads them and enforces them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field, field_validator

from pi_semantic_validator.models import ReplayClass


class TrustZone(BaseModel):
    """A single trust boundary zone."""

    zone_id: str
    description: str = ""
    owner: str = ""
    # Endpoint path patterns belonging to this zone
    endpoint_patterns: List[str] = Field(default_factory=list)
    # Service name patterns belonging to this zone
    service_patterns: List[str] = Field(default_factory=list)
    # Database/resource patterns belonging to this zone
    resource_patterns: List[str] = Field(default_factory=list)


class TrustBoundaryRule(BaseModel):
    """A rule forbidding or requiring crossings between zones."""

    rule_id: str
    from_zone: str
    to_zone: str
    # "FORBIDDEN" = crossing this boundary is always a violation
    # "REQUIRES_AUTH" = crossing allowed only with auth invariant match
    # "REQUIRES_AUDIT" = crossing allowed but must be logged
    action: Literal["FORBIDDEN", "REQUIRES_AUTH", "REQUIRES_AUDIT", "ALLOWED"] = "FORBIDDEN"
    # Auth invariant types required if action == REQUIRES_AUTH
    required_auth_invariants: List[str] = Field(default_factory=list)
    description: str = ""


class LayerDefinition(BaseModel):
    """A single architectural layer (tier)."""

    layer_id: str
    description: str = ""
    # Module path patterns that belong to this layer
    module_patterns: List[str] = Field(default_factory=list)
    # File path patterns that belong to this layer
    file_patterns: List[str] = Field(default_factory=list)
    # Endpoint path patterns served by this layer
    endpoint_patterns: List[str] = Field(default_factory=list)
    # Layers that may NOT import this layer (inversion protection)
    forbidden_importers: List[str] = Field(default_factory=list)


class LayerRule(BaseModel):
    """A rule enforcing layer separation."""

    rule_id: str
    from_layer: str
    to_layer: str
    # "FORBIDDEN" = import/call from from_layer to to_layer is a violation
    # "REQUIRES_GATEWAY" = must go through an explicit gateway module
    action: Literal["FORBIDDEN", "REQUIRES_GATEWAY", "ALLOWED"] = "FORBIDDEN"
    gateway_modules: List[str] = Field(default_factory=list)
    description: str = ""


class MutationRule(BaseModel):
    """A rule classifying acceptable mutation behavior per endpoint pattern."""

    rule_id: str
    # Regex or glob pattern matching endpoint_template
    endpoint_pattern: str
    methods: List[str] = Field(default_factory=list)
    # The ONLY allowed mutation classes for matching endpoints
    allowed_mutation_classes: List[str] = Field(default_factory=list)
    # If True, any stateful mutation MUST have an auth invariant
    requires_auth_for_mutation: bool = True
    # If True, destructive mutation MUST have replay_unsafe classification
    requires_replay_unsafe_for_destructive: bool = True
    description: str = ""


class ReplayRule(BaseModel):
    """A rule governing replay safety classification per endpoint."""

    rule_id: str
    endpoint_pattern: str
    methods: List[str] = Field(default_factory=list)
    # Required replay class for matching endpoints
    required_replay_class: str = ReplayClass.IDEMPOTENT
    # If True, endpoint MUST be sandboxed for replay
    sandbox_required: bool = False
    # If True, production replay is strictly prohibited
    production_replay_prohibited: bool = True
    # Allowed mutation classes that may be replayed in sandbox
    sandbox_replayable_mutations: List[str] = Field(default_factory=list)
    description: str = ""


class BlastRadiusLimit(BaseModel):
    """Numeric bounds for blast radius validation."""

    # Topology
    max_dependencies_per_endpoint: int = Field(default=16, ge=0)
    max_cross_service_edges: int = Field(default=64, ge=0)
    max_fanout_per_endpoint: int = Field(default=8, ge=0)
    max_graph_depth: int = Field(default=6, ge=0)
    max_topology_complexity_score: float = Field(default=100.0, ge=0.0)

    # Auth surface
    max_auth_fields_per_endpoint: int = Field(default=8, ge=0)
    max_auth_invariants_per_graph: int = Field(default=128, ge=0)
    max_unconfirmed_auth_bindings: int = Field(default=32, ge=0)

    # Replay propagation
    max_replay_scope_nodes: int = Field(default=256, ge=0)
    max_replay_propagation_depth: int = Field(default=6, ge=0)
    max_side_effect_bound_endpoints: int = Field(default=32, ge=0)

    # Drift
    max_structural_delta_score: float = Field(default=0.3, ge=0.0, le=1.0)
    max_semantic_delta_score: float = Field(default=0.3, ge=0.0, le=1.0)
    max_drift_score: float = Field(default=0.2, ge=0.0, le=1.0)
    max_auth_mutation_count: int = Field(default=4, ge=0)


class StateWriterRule(BaseModel):
    """A rule controlling which layers may write to which state stores."""

    rule_id: str
    layer_id: str
    # Database / cache / queue patterns this layer may write to
    allowed_writers: List[str] = Field(default_factory=list)
    # If True, any write not matching allowed_writers is a violation
    fail_closed: bool = True
    description: str = ""


class ForbiddenImportRule(BaseModel):
    """A rule forbidding specific imports within a layer."""

    rule_id: str
    layer_id: str
    # Module patterns that are FORBIDDEN to import in this layer
    forbidden_modules: List[str] = Field(default_factory=list)
    # If True, violation is CRITICAL
    is_critical: bool = False
    description: str = ""


class ArchitecturePolicy(BaseModel):
    """Root architecture policy document.

    The single source of truth for all governance rules.
    Loaded from architecture-policy.json.
    """

    policy_id: str
    policy_version: str = "1.0.0"
    description: str = ""
    generated_at: str = Field(default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())

    # Trust boundaries
    trust_zones: List[TrustZone] = Field(default_factory=list)
    trust_boundary_rules: List[TrustBoundaryRule] = Field(default_factory=list)

    # Layer enforcement
    layers: List[LayerDefinition] = Field(default_factory=list)
    layer_rules: List[LayerRule] = Field(default_factory=list)

    # Mutation governance
    mutation_rules: List[MutationRule] = Field(default_factory=list)

    # Replay governance
    replay_rules: List[ReplayRule] = Field(default_factory=list)

    # Blast radius bounds
    blast_radius_limits: BlastRadiusLimit = Field(default_factory=BlastRadiusLimit)

    # State writer control
    state_writer_rules: List[StateWriterRule] = Field(default_factory=list)

    # Forbidden imports
    forbidden_import_rules: List[ForbiddenImportRule] = Field(default_factory=list)

    # Global fail-closed flag: if a resource is not matched by any rule,
    # does the validator treat it as a violation?
    global_fail_closed: bool = True

    # Schema version for compatibility checks
    schema_version: str = "1.0.0"

    @field_validator("trust_zones")
    @classmethod
    def _unique_zone_ids(cls, v: List[TrustZone]) -> List[TrustZone]:
        ids = [z.zone_id for z in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate trust_zone IDs")
        return v

    @field_validator("layers")
    @classmethod
    def _unique_layer_ids(cls, v: List[LayerDefinition]) -> List[LayerDefinition]:
        ids = [l.layer_id for l in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate layer IDs")
        return v

    @property
    def trust_zone_ids(self) -> Set[str]:
        return {z.zone_id for z in self.trust_zones}

    @property
    def layer_ids(self) -> Set[str]:
        return {l.layer_id for l in self.layers}

    def compute_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def get_zone_for_endpoint(self, endpoint: str) -> Optional[TrustZone]:
        """Deterministic zone assignment by first matching pattern."""
        for zone in self.trust_zones:
            for pattern in zone.endpoint_patterns:
                if _glob_match(endpoint, pattern):
                    return zone
        return None

    def get_layer_for_endpoint(self, endpoint: str) -> Optional[LayerDefinition]:
        """Deterministic layer assignment by first matching pattern."""
        for layer in self.layers:
            for pattern in layer.endpoint_patterns:
                if _glob_match(endpoint, pattern):
                    return layer
        return None

    def get_mutation_rule_for_endpoint(self, endpoint: str, method: str) -> Optional[MutationRule]:
        """First matching mutation rule."""
        for rule in self.mutation_rules:
            if _glob_match(endpoint, rule.endpoint_pattern):
                if not rule.methods or method.upper() in [m.upper() for m in rule.methods]:
                    return rule
        return None

    def get_replay_rule_for_endpoint(self, endpoint: str, method: str) -> Optional[ReplayRule]:
        """First matching replay rule."""
        for rule in self.replay_rules:
            if _glob_match(endpoint, rule.endpoint_pattern):
                if not rule.methods or method.upper() in [m.upper() for m in rule.methods]:
                    return rule
        return None


def _glob_match(value: str, pattern: str) -> bool:
    """Deterministic glob-like matching with explicit * and ? wildcards.

    No regex engine dependency. Bounded execution.
    """
    # Normalize
    if pattern == "*":
        return True
    if pattern == value:
        return True
    # Simple glob: only * and ? supported
    pi = 0
    vi = 0
    star_idx = -1
    match_idx = 0
    while vi < len(value):
        if pi < len(pattern) and (pattern[pi] == "?" or pattern[pi] == value[vi]):
            vi += 1
            pi += 1
        elif pi < len(pattern) and pattern[pi] == "*":
            star_idx = pi
            match_idx = vi
            pi += 1
        elif star_idx != -1:
            pi = star_idx + 1
            match_idx += 1
            vi = match_idx
        else:
            return False
    # Trailing stars
    while pi < len(pattern) and pattern[pi] == "*":
        pi += 1
    return pi == len(pattern)


def load_policy(path: Path | str) -> ArchitecturePolicy:
    """Load and validate an architecture-policy.json file."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return ArchitecturePolicy.model_validate(raw)
