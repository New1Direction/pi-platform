"""pi-semantic-validator: Immutable type manifest for the Deterministic Semantic Governance Runtime.

No inference. No LLM calls. No probabilistic scoring.
Every model is evidence-bound, schema-validated, and fail-closed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────
#  Epistemic Primitives (mirrored from pi-semantic-recon for independence)
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


class WorkerStatus(str):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    INVALID_INPUT = "INVALID_INPUT"
    TIMEOUT = "TIMEOUT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    VERIFICATION_MISMATCH = "VERIFICATION_MISMATCH"
    OBJECTIVE_DRIFT_DETECTED = "OBJECTIVE_DRIFT_DETECTED"
    BRANCH_OVERFLOW = "BRANCH_OVERFLOW"
    INVALID_OUTPUT = "INVALID_OUTPUT"


# ──────────────────────────────
#  Artifact Envelopes (consumed from pi-semantic-recon)
# ──────────────────────────────

class SemanticField(BaseModel):
    """Typed primitive inside a SemanticIRTrace."""

    path: str
    inferred_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    entropy_score: float = Field(..., ge=0.0, le=1.0)
    example_value: Optional[str] = None


class SemanticIRTrace(BaseModel):
    """Recon artifact: endpoint semantic typing."""

    endpoint_template: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    fields: List[SemanticField] = Field(default_factory=list)
    is_frozen: bool = False
    frozen_at: Optional[datetime] = None
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "SemanticTyperNode"


class StateEdge(BaseModel):
    """Dependency edge from recon."""

    upstream_endpoint: str
    upstream_field: str
    downstream_endpoint: str
    downstream_field: str
    carrier_mechanism: Literal["HEADER", "COOKIE", "QUERY", "BODY"] = "HEADER"


class DependencyGraph(BaseModel):
    """Recon artifact: endpoint dependency topology."""

    edges: List[StateEdge] = Field(default_factory=list)
    nodes: List[str] = Field(default_factory=list)
    session_window_id: str
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "FlowMapperNode"


class SynthesizedSpec(BaseModel):
    """Recon artifact: synthesized OpenAPI spec."""

    openapi_version: Literal["3.1.0"] = "3.1.0"
    spec_json: str
    validation_errors: List[str] = Field(default_factory=list)
    is_valid: bool = False
    synthesized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "SpecSynthesizerNode"
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    verification_status: str = Field(default="UNVERIFIED")


class BehavioralDelta(BaseModel):
    """Delta from pi-semantic-diff."""

    path: str
    action: str
    observed_status: int
    expected_status: int
    contradiction_detected: bool
    message: Optional[str] = None


class SemanticDiff(BaseModel):
    """Structured semantic comparison substrate."""

    structural_delta_score: float = Field(..., ge=0.0, le=1.0)
    semantic_delta_score: float = Field(..., ge=0.0, le=1.0)
    added_fields: List[str] = Field(default_factory=list)
    removed_fields: List[str] = Field(default_factory=list)
    type_mutations: List[str] = Field(default_factory=list)
    auth_mutations: List[str] = Field(default_factory=list)
    endpoint_stable: bool = True
    method_stable: bool = True
    replay_equivalence: str = Field(default="CONTESTED")
    drift_score: float = Field(default=0.0, ge=0.0, le=1.0)
    canonicalized: bool = True


class AuthInvariant(BaseModel):
    """Recon artifact: auth invariant."""

    invariant_id: str
    invariant_type: str
    description: str
    rotation_class: str = Field(default="UNKNOWN")
    evidence_refs: List[str] = Field(default_factory=list)
    binding_refs: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    replay_confirmed_endpoints: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    replay_confirmed: bool = False


class ProtocolStateMachine(BaseModel):
    """Recon artifact: protocol FSM."""

    fsm_id: str
    nodes: List[Any] = Field(default_factory=list)
    edges: List[Any] = Field(default_factory=list)
    max_nodes: int = 64
    max_edges: int = 256
    max_fanout: int = 8
    max_depth: int = 6
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────
#  Governance Primitives
# ──────────────────────────────

class GovernanceViolation(BaseModel):
    """Immutable record of a governance breach."""

    violation_id: str
    rule: str
    pass_name: str
    severity: Literal["WARNING", "ERROR", "CRITICAL"] = "ERROR"
    context: Dict[str, Any] = Field(default_factory=dict)
    action_taken: str = "HALT"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationBoundsConfig(BaseModel):
    """Bounded execution configuration."""

    max_violations_per_pass: int = Field(default=128, ge=1)
    max_endpoints_per_trace: int = Field(default=1024, ge=1)
    max_edges_per_graph: int = Field(default=512, ge=1)
    max_fields_per_endpoint: int = Field(default=256, ge=1)
    max_policy_rules: int = Field(default=4096, ge=1)
    max_blast_radius_depth: int = Field(default=6, ge=1, le=16)
    max_replay_scope_nodes: int = Field(default=256, ge=1)
    max_mutation_chain_length: int = Field(default=32, ge=1)
    max_provenance_depth: int = Field(default=16, ge=1)

    model_config = {"frozen": True}


class WorkerEnvelope(BaseModel):
    """Deterministic worker input envelope for validation passes."""

    execution_id: str
    pass_name: str
    artifacts_hash: str
    policy_hash: str
    bounds: ValidationBoundsConfig = Field(default_factory=ValidationBoundsConfig)
    depth: int = Field(default=0, ge=0, le=3)
    provenance: List[str] = Field(default_factory=list)


class WorkerResponse(BaseModel):
    """Deterministic worker response envelope."""

    execution_id: str
    pass_name: str
    status: str = Field(default=WorkerStatus.SUCCESS)
    violations: List[GovernanceViolation] = Field(default_factory=list)
    evidence_count: int = 0
    output_hash: str = ""
    execution_time_ms: int = 0

    @field_validator("status")
    @classmethod
    def _valid_status(cls, v: str) -> str:
        valid = {
            WorkerStatus.SUCCESS,
            WorkerStatus.FAILURE,
            WorkerStatus.RETRYABLE_FAILURE,
            WorkerStatus.INVALID_INPUT,
            WorkerStatus.TIMEOUT,
            WorkerStatus.INSUFFICIENT_EVIDENCE,
            WorkerStatus.VERIFICATION_MISMATCH,
            WorkerStatus.OBJECTIVE_DRIFT_DETECTED,
            WorkerStatus.BRANCH_OVERFLOW,
            WorkerStatus.INVALID_OUTPUT,
        }
        if v not in valid:
            raise ValueError(f"Invalid worker status: {v}")
        return v


# ──────────────────────────────
#  Validator Runtime Models
# ──────────────────────────────

class ValidationArtifact(BaseModel):
    """A single artifact loaded for validation with its runtime envelope."""

    artifact_id: str
    artifact_type: Literal[
        "SemanticIRTrace",
        "DependencyGraph",
        "SynthesizedSpec",
        "SemanticDiff",
        "AuthInvariant",
        "ProtocolStateMachine",
        "Unknown",
    ]
    payload: Any  # deserialized pydantic model or raw dict
    semantic_hash: str = ""
    provenance: List[str] = Field(default_factory=list)
    epistemic_state: str = Field(default=EpistemicState.OBSERVED)
    source_execution_id: str = ""


class ValidationReport(BaseModel):
    """Final deterministic validation report."""

    report_id: str
    execution_id: str
    policy_hash: str
    artifacts_hash: str
    status: Literal["PASS", "FAIL", "INDETERMINATE"] = "FAIL"
    pass_results: Dict[str, WorkerResponse] = Field(default_factory=dict)
    violations: List[GovernanceViolation] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    bounds: ValidationBoundsConfig = Field(default_factory=ValidationBoundsConfig)

    @property
    def has_critical(self) -> bool:
        return any(v.severity == "CRITICAL" for v in self.violations)

    @property
    def has_errors(self) -> bool:
        return any(v.severity in ("ERROR", "CRITICAL") for v in self.violations)
