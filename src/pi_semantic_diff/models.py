"""pi-semantic-diff: Immutable delta models for the Deterministic Behavioral Delta Runtime.

No inference. No LLM calls. No probabilistic scoring.
Every model is evidence-bound, schema-validated, and fail-closed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Epistemic Primitives (mirrored for independence)
# ──────────────────────────────


class EpistemicState(str):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"
    REPLAY_CONFIRMED = "REPLAY_CONFIRMED"
    CONTESTED = "CONTESTED"
    REJECTED = "REJECTED"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"


class MutationClass(str):
    IDEMPOTENT_READ = "IDEMPOTENT_READ"
    STATEFUL_MUTATION = "STATEFUL_MUTATION"
    DESTRUCTIVE_MUTATION = "DESTRUCTIVE_MUTATION"
    NON_DETERMINISTIC = "NON_DETERMINISTIC"
    REPLAY_UNSAFE = "REPLAY_UNSAFE"
    SIDE_EFFECT_BOUND = "SIDE_EFFECT_BOUND"
    UNKNOWN = "UNKNOWN"


class ReplayClass(str):
    PURE_REPLAYABLE = "PURE_REPLAYABLE"
    IDEMPOTENT = "IDEMPOTENT"
    NON_REPLAYABLE = "NON_REPLAYABLE"
    SIDE_EFFECT_RISK = "SIDE_EFFECT_RISK"


# ──────────────────────────────
#  Graph Primitives (shared with recon)
# ──────────────────────────────


class SemanticField(BaseModel):
    path: str
    inferred_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    entropy_score: float = Field(..., ge=0.0, le=1.0)
    example_value: Optional[str] = None
    model_config = {"frozen": True}


class SemanticIRTrace(BaseModel):
    endpoint_template: str
    method: str
    fields: List[SemanticField] = Field(default_factory=list)
    is_frozen: bool = False
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: str = ""
    mutation_class: str = "UNKNOWN"
    replay_class: str = "UNKNOWN"
    sandbox_required: bool = False
    production_replay_prohibited: bool = False
    model_config = {"frozen": True}


class StateEdge(BaseModel):
    upstream_endpoint: str
    upstream_field: str
    downstream_endpoint: str
    downstream_field: str
    carrier_mechanism: Literal["HEADER", "COOKIE", "QUERY", "BODY"] = "HEADER"
    model_config = {"frozen": True}


class DependencyGraph(BaseModel):
    edges: List[StateEdge] = Field(default_factory=list)
    nodes: List[str] = Field(default_factory=list)
    session_window_id: str = ""
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: str = ""
    model_config = {"frozen": True}


class AuthInvariant(BaseModel):
    invariant_id: str
    invariant_type: str = ""
    description: str = ""
    rotation_class: str = "UNKNOWN"
    evidence_refs: List[str] = Field(default_factory=list)
    binding_refs: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    replay_confirmed_endpoints: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    replay_confirmed: bool = False
    model_config = {"frozen": True}


# ──────────────────────────────
#  Delta Primitives
# ──────────────────────────────


class FieldDelta(BaseModel):
    """Immutable record of a single field change between two traces."""

    field_path: str
    delta_type: Literal["ADDED", "REMOVED", "TYPE_CHANGED", "CONFIDENCE_CHANGED", "ENTROPY_CHANGED"]
    baseline_value: Optional[Any] = None
    modified_value: Optional[Any] = None
    severity: Literal["INFO", "WARNING", "CRITICAL"] = "INFO"
    model_config = {"frozen": True}


class EndpointDelta(BaseModel):
    """Immutable record of endpoint-level behavioral delta."""

    endpoint_template: str
    method: str
    # Presence delta
    presence: Literal["UNCHANGED", "ADDED", "REMOVED"] = "UNCHANGED"
    # Field-level deltas
    field_deltas: List[FieldDelta] = Field(default_factory=list)
    # Mutation class transition
    baseline_mutation_class: str = "UNKNOWN"
    modified_mutation_class: str = "UNKNOWN"
    mutation_class_transition: bool = False
    # Replay class transition
    baseline_replay_class: str = "UNKNOWN"
    modified_replay_class: str = "UNKNOWN"
    replay_class_transition: bool = False
    # Auth requirement delta
    auth_required_delta: bool = False
    auth_mechanism_delta: bool = False
    # Deterministic hash of this delta
    delta_hash: str = ""
    provenance: List[str] = Field(default_factory=list)
    model_config = {"frozen": True}


class DependencyDelta(BaseModel):
    """Immutable record of dependency graph evolution."""

    delta_type: Literal["EDGE_ADDED", "EDGE_REMOVED", "EDGE_CHANGED", "NODE_ADDED", "NODE_REMOVED"]
    edge: Optional[StateEdge] = None
    node: Optional[str] = None
    upstream_endpoint: str = ""
    downstream_endpoint: str = ""
    model_config = {"frozen": True}


class AuthDelta(BaseModel):
    """Immutable record of auth invariant evolution."""

    invariant_id: str = ""
    delta_type: Literal["ADDED", "REMOVED", "ROTATION_CLASS_CHANGED", "BINDING_CHANGED", "CONFIDENCE_CHANGED"]
    affected_endpoints_delta: int = 0
    replay_confirmed_delta: int = 0
    model_config = {"frozen": True}


class ReplaySurfaceDelta(BaseModel):
    """Immutable record of replay surface change."""

    endpoint_template: str
    method: str
    replayable_delta: bool = False
    sandbox_required_delta: bool = False
    production_replay_prohibited_delta: bool = False
    model_config = {"frozen": True}


# ──────────────────────────────
#  Diff Report
# ──────────────────────────────


class SemanticDiffReport(BaseModel):
    """Deterministic behavioral delta report between two runtime snapshots."""

    report_id: str
    baseline_execution_id: str = ""
    modified_execution_id: str = ""
    # Structural metrics
    endpoint_count_delta: int = 0
    edge_count_delta: int = 0
    node_count_delta: int = 0
    field_count_delta: int = 0
    # Semantic metrics
    structural_delta_score: float = 0.0
    semantic_delta_score: float = 0.0
    drift_score: float = 0.0
    # Catalogued deltas
    endpoint_deltas: List[EndpointDelta] = Field(default_factory=list)
    dependency_deltas: List[DependencyDelta] = Field(default_factory=list)
    auth_deltas: List[AuthDelta] = Field(default_factory=list)
    replay_surface_deltas: List[ReplaySurfaceDelta] = Field(default_factory=list)
    # State mutation expansion
    state_mutation_expansion: int = 0
    destructive_mutation_expansion: int = 0
    idempotent_read_regression: int = 0
    # Replay surface metrics
    replay_surface_expansion: int = 0
    replay_unsafe_expansion: int = 0
    # Dependency evolution
    dependency_graph_evolution_score: float = 0.0
    # Protocol contract drift
    protocol_contract_drift_detected: bool = False
    contract_violations: List[str] = Field(default_factory=list)
    # Deterministic hash
    report_hash: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = json.dumps(
            self.model_dump(exclude={"report_hash", "generated_at"}),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()
