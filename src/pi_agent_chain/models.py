"""pi-semantic-recon: Immutable type manifest for the Deterministic Semantic DAG."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ──────────────────────────────
#  Primitive Enums (top-level)
# ──────────────────────────────

class ReplayClass(str):
    """Replay safety classification for acquired traffic."""

    PURE_REPLAYABLE = "PURE_REPLAYABLE"
    IDEMPOTENT = "IDEMPOTENT"
    NON_REPLAYABLE = "NON_REPLAYABLE"
    SIDE_EFFECT_RISK = "SIDE_EFFECT_RISK"


class EquivalenceClass(str):
    """Semantic replay equivalence classification.

    NOT byte equality. Behavioral meaning preservation.
    """

    STRICT_EQUIVALENT = "STRICT_EQUIVALENT"
    SEMANTIC_EQUIVALENT = "SEMANTIC_EQUIVALENT"
    PARTIAL_EQUIVALENT = "PARTIAL_EQUIVALENT"
    NON_EQUIVALENT = "NON_EQUIVALENT"
    CONTESTED = "CONTESTED"


class EpistemicState(str):
    """Explicit knowledge-state for semantic artifacts.

    OBSERVED      — Raw runtime truth; zero inference.
    INFERRED      — Produced by deterministic cognitive nodes.
    VERIFIED      — Passed differential verification.
    REPLAY_CONFIRMED — Verified through replay equivalence (Phase 5).
    CONTESTED     — Verification contradictions detected.
    REJECTED      — Semantic claim rejected by quorum (Phase 5).
    STALE         — Runtime truth has drifted.
    INVALIDATED   — Superseded or proven wrong.
    """

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"
    REPLAY_CONFIRMED = "REPLAY_CONFIRMED"
    CONTESTED = "CONTESTED"
    REJECTED = "REJECTED"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"


# ──────────────────────────────
#  Node 0: Acquisition Layer
# ──────────────────────────────

class RuntimeTruthEnvelope(BaseModel):
    """Root immutable runtime fact object.

    Anchors provenance for every packet entering the semantic DAG.
    Zero inference. Only observation.
    """

    capture_id: str
    flow_id: str
    observed_at: datetime = Field(default_factory=datetime.utcnow)
    transport: Literal["HTTP1", "HTTP2", "HTTP3"] = "HTTP1"
    tls: bool = True
    source: Literal["MITMPROXY", "PCAP", "HAR", "MANUAL"] = "MANUAL"
    packet_hash: str
    canonical_hash: str
    replay_class: str = Field(default=ReplayClass.IDEMPOTENT)
    canonicalized_headers: List[Tuple[str, str]] = Field(default_factory=list)
    content_type_normalized: Optional[str] = None
    body_encoding: Literal["utf-8", "binary", "base64", "unknown"] = "utf-8"


class GovernedPacket(BaseModel):
    """Canonical packet bound to its runtime truth envelope.

    This is what the semantic DAG actually consumes.
    """

    truth: RuntimeTruthEnvelope
    packet: "NormalizedTrafficPacket"

    def compute_composite_hash(self) -> str:
        combined = self.truth.canonical_hash + self.packet.compute_hash()
        return hashlib.sha256(combined.encode()).hexdigest()


# ──────────────────────────────
#  Node 1: Ingress Parser
# ──────────────────────────────

class NormalizedTrafficPacket(BaseModel):
    """Output of Node 1: Ingress Parser.

    Now includes content negotiation metadata and payload normalization
    for real-world traffic noise (Gap 1).
    """

    timestamp: int
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    uri: str
    raw_headers: List[Tuple[str, str]] = Field(default_factory=list)
    raw_payload: Optional[str] = None
    response_status: int = Field(..., ge=100, le=599)
    response_headers: List[Tuple[str, str]] = Field(default_factory=list)
    response_payload: Optional[str] = None
    host: str = "unknown"
    scheme: str = "https"

    # Gap 1: Content negotiation + payload normalization
    request_payload_norm: Optional[PayloadNormalization] = None
    response_payload_norm: Optional[PayloadNormalization] = None
    content_meta: Optional[ContentNegotiationMeta] = None

    @property
    def endpoint_path_template(self) -> str:
        path = self.uri.split("?")[0]
        return path

    def compute_hash(self) -> str:
        payload = json.dumps(
            self.model_dump(exclude={"timestamp"}),
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Node 2: Structural Extractor
# ──────────────────────────────

class ExtractedProtocolSkeleton(BaseModel):
    """Output of Node 2: Deterministic Structural Extractor."""

    request_uri_segments: List[str] = Field(default_factory=list)
    request_query_keys: List[str] = Field(default_factory=list)
    request_header_keys: List[str] = Field(default_factory=list)
    request_payload_keys_flattened: List[str] = Field(default_factory=list)
    response_header_keys: List[str] = Field(default_factory=list)
    response_payload_keys_flattened: List[str] = Field(default_factory=list)

    def compute_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Node 3: Semantic Typing Engine
# ──────────────────────────────

class SemanticField(BaseModel):
    """Typed primitive inside a SemanticIRTrace."""

    path: str
    inferred_type: str = Field(
        ...,
        pattern=r"^(UUIDv4|UUIDv1|UnixTimestamp|UnixTimestampMS|JWT|JWT_Payload|"
        r"Base64|HexDigest|URL|Email|IPv4|IPv6|ISO8601|"
        r"UNKNOWN_HEX|UNKNOWN_STR|STRING|INTEGER|NUMBER|BOOLEAN|OBJECT|ARRAY)$",
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    entropy_score: float = Field(..., ge=0.0, le=1.0)
    example_value: Optional[str] = None


class SemanticIRTrace(BaseModel):
    """Output of Node 3: Semantic Typing Engine.

    If confidence drops below the governance threshold, is_frozen remains False
    and the field list may contain UNKNOWN placeholders (fail-closed).
    """

    endpoint_template: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    fields: List[SemanticField] = Field(default_factory=list)
    is_frozen: bool = False
    frozen_at: Optional[datetime] = None
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "SemanticTyperNode"

    def compute_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Node 4: Dependency Mapper
# ──────────────────────────────

class StateEdge(BaseModel):
    """A single directed dependency edge."""

    upstream_endpoint: str
    upstream_field: str
    downstream_endpoint: str
    downstream_field: str
    carrier_mechanism: Literal["HEADER", "COOKIE", "QUERY", "BODY"] = "HEADER"


class DependencyGraph(BaseModel):
    """Output of Node 4: Dependency Mapper."""

    edges: List[StateEdge] = Field(default_factory=list)
    nodes: List[str] = Field(default_factory=list)
    session_window_id: str
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "FlowMapperNode"

    def compute_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Node 5: Spec Synthesizer
# ──────────────────────────────

class SynthesizedSpec(BaseModel):
    """Output of Node 5: Spec Synthesizer."""

    openapi_version: Literal["3.1.0"] = "3.1.0"
    spec_json: str
    validation_errors: List[str] = Field(default_factory=list)
    is_valid: bool = False
    synthesized_at: datetime = Field(default_factory=datetime.utcnow)
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: Optional[str] = None
    generated_by: str = "SpecSynthesizerNode"
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    verification_status: str = Field(default="UNVERIFIED")

    @field_validator("spec_json")
    @classmethod
    def must_be_valid_json(cls, v: str) -> str:
        json.loads(v)
        return v

    def openapi_dict(self) -> Dict[str, Any]:
        return json.loads(self.spec_json)


# ──────────────────────────────
#  Node 6: Differential Verifier
# ──────────────────────────────

class BehavioralDelta(BaseModel):
    """A single differential mismatch from Node 6."""

    path: str
    action: str
    observed_status: int
    expected_status: int
    contradiction_detected: bool
    message: Optional[str] = None


class SemanticDiff(BaseModel):
    """Structured semantic comparison substrate for replay governance.

    Operates on Canonical Semantic IR, not raw bytes.
    """

    structural_delta_score: float = Field(..., ge=0.0, le=1.0)
    semantic_delta_score: float = Field(..., ge=0.0, le=1.0)
    added_fields: List[str] = Field(default_factory=list)
    removed_fields: List[str] = Field(default_factory=list)
    type_mutations: List[str] = Field(default_factory=list)
    auth_mutations: List[str] = Field(default_factory=list)
    endpoint_stable: bool = True
    method_stable: bool = True
    replay_equivalence: str = Field(default=EquivalenceClass.CONTESTED)
    drift_score: float = Field(default=0.0, ge=0.0, le=1.0)
    canonicalized: bool = True


class VerificationReport(BaseModel):
    """Output of Node 6: Differential Verification Engine."""

    passed: bool = False
    behavioral_deltas: List[BehavioralDelta] = Field(default_factory=list)
    spec_coverage_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    tested_endpoints: int = 0
    total_endpoints: int = 0
    verified_at: datetime = Field(default_factory=datetime.utcnow)

    def compute_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Ledger & Governance
# ──────────────────────────────

class ExecutionTrace(BaseModel):
    """Immutable ledger entry for deterministic replay."""

    trace_id: str
    node_name: str
    input_payload_hash: str
    llm_seed: int
    llm_temperature: float = 0.0
    raw_output: str
    is_valid_type: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None


class GovernanceConfig(BaseModel):
    """Runtime governance configuration for pi-semantic-recon."""

    max_inference_iterations: int = Field(default=3, ge=1, le=10)
    semantic_confidence_threshold: float = Field(default=0.87, ge=0.0, le=1.0)
    enable_semantic_freezing: bool = True
    bounded_context_window: int = Field(default=12000, ge=1024)
    verification_replay_seed: int = 1337


# ──────────────────────────────
#  Hyper-Rigid Governance Manifest Primitives
# ──────────────────────────────

class WorkerStatus(str):
    """Finite-state worker emission statuses.

    Every worker MUST emit exactly one of these.
    No hidden states. No partial success.
    """

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


class WorkerResponse(BaseModel):
    """Universal worker response envelope.

    Workers are replaceable pure functions:
        f(input_envelope) -> WorkerResponse

    The runtime owns state transitions. Workers only propose.
    """

    root_goal_id: str
    worker_id: str
    status: str = Field(default=WorkerStatus.SUCCESS)
    artifacts: List[dict] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    next_state: Optional[str] = None
    input_hash: str = ""
    output_hash: str = ""
    execution_time_ms: int = 0
    tokens_consumed: int = 0

    # Deterministic replay metadata
    execution_id: str = ""
    parent_execution_id: Optional[str] = None
    trace_hash: str = ""
    prompt_hash: str = ""
    model_identifier: str = ""
    schema_version: str = "1.0.0"

    @field_validator("status")
    @classmethod
    def _valid_status(cls, v: str) -> str:
        valid = {WorkerStatus.SUCCESS, WorkerStatus.FAILURE, WorkerStatus.RETRYABLE_FAILURE,
                 WorkerStatus.INVALID_INPUT, WorkerStatus.TIMEOUT, WorkerStatus.INSUFFICIENT_EVIDENCE,
                 WorkerStatus.VERIFICATION_MISMATCH, WorkerStatus.OBJECTIVE_DRIFT_DETECTED,
                 WorkerStatus.BRANCH_OVERFLOW, WorkerStatus.INVALID_OUTPUT}
        if v not in valid:
            raise ValueError(f"Invalid worker status: {v}")
        return v


class WorkerEnvelope(BaseModel):
    """Zero-trust worker input envelope.

    Workers feel computationally trapped. That is intentional.
    All required state is explicit. No hidden memory.
    """

    root_goal_id: str
    worker_id: str
    state_id: str
    input_ref: str
    input_payload: str = ""
    execution_budget: dict = Field(default_factory=lambda: {
        "max_tokens": 2500,
        "max_seconds": 20,
        "max_retries": 2,
    })
    objective_scope: dict = Field(default_factory=dict)
    allowed_transitions: List[str] = Field(default_factory=list)
    allowed_workers: List[str] = Field(default_factory=list)
    depth: int = Field(default=0, ge=0, le=3)
    branch_count: int = Field(default=0, ge=0, le=8)
    provenance: List[str] = Field(default_factory=list)

    # Deterministic replay metadata
    execution_id: str = ""
    parent_execution_id: Optional[str] = None
    trace_hash: str = ""
    prompt_hash: str = ""
    input_hash: str = ""
    model_identifier: str = ""
    schema_version: str = "1.0.0"


class TransitionRule(BaseModel):
    """A single allowed state transition.

    Runtime validates every transition against this rule set.
    Invalid transitions -> HARD_FAIL.
    """

    from_state: str
    to_state: str
    required_worker_status: str = WorkerStatus.SUCCESS
    max_depth: int = 3
    max_branch_count: int = 8


class RuntimeState(str):
    """Canonical pipeline states.

    REGISTERED → SCOPED → CAPTURE_READY → CAPTURING → NORMALIZING → EXTRACTING →
    VERIFYING → ASSEMBLING_IR → GENERATING_SPEC → COMPLETED
    """

    REGISTERED = "REGISTERED"
    SCOPED = "SCOPED"
    CAPTURE_READY = "CAPTURE_READY"
    CAPTURING = "CAPTURING"
    NORMALIZING = "NORMALIZING"
    EXTRACTING = "EXTRACTING"
    VERIFYING = "VERIFYING"
    ASSEMBLING_IR = "ASSEMBLING_IR"
    GENERATING_SPEC = "GENERATING_SPEC"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY_PENDING = "RETRY_PENDING"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"


class GovernanceViolation(BaseModel):
    """Immutable record of a runtime governance breach.

    Stored in the ledger. Never deleted.
    """

    violation_id: str
    rule: str
    worker_id: str
    root_goal_id: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    severity: Literal["WARNING", "ERROR", "CRITICAL"] = "ERROR"
    context: dict = Field(default_factory=dict)
    action_taken: str = "HALT"


# ──────────────────────────────
#  Phase 3: Auth Consistency Models
# ──────────────────────────────

class AuthEvidenceType(str):
    """Observable evidence of authentication mechanisms."""

    BEARER_HEADER = "BEARER_HEADER"
    BASIC_HEADER = "BASIC_HEADER"
    API_KEY_HEADER = "API_KEY_HEADER"
    COOKIE_TOKEN = "COOKIE_TOKEN"
    CSRF_TOKEN = "CSRF_TOKEN"
    SESSION_COOKIE = "SESSION_COOKIE"
    JWT_HEADER = "JWT_HEADER"
    OAUTH_FLOW = "OAUTH_FLOW"
    UNKNOWN_AUTH = "UNKNOWN_AUTH"


class AuthEvidence(BaseModel):
    """A single observed authentication datum.

    Evidence-bound. Zero inference. Only what was observed.
    """

    evidence_id: str
    trace_id: str
    packet_id: str
    evidence_type: str
    field_path: str
    carrier: Literal["HEADER", "COOKIE", "QUERY", "BODY"]
    observed_value_hash: str
    observed_at: datetime = Field(default_factory=datetime.utcnow)
    endpoint_template: str = ""
    method: str = ""
    status_code: int = 0


class AuthBinding(BaseModel):
    """An observed coupling between two auth carrier mechanisms.

    Example: cookie and CSRF-token always appear together.
    """

    binding_id: str
    carrier_a: str
    field_path_a: str
    carrier_b: str
    field_path_b: str
    co_occurrence_count: int = 0
    disjoint_count: int = 0
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_refs: List[str] = Field(default_factory=list)
    epistemic_state: str = Field(default=EpistemicState.OBSERVED)


class AuthInvariant(BaseModel):
    """An evidence-bound auth invariant ready for governance validation.

    NOT inferred from naming. Only from observed, replay-confirmed patterns.
    """

    invariant_id: str
    invariant_type: str  # "TOKEN_REUSE", "CSRF_COUPLING", "COOKIE_HEADER_BINDING", "SESSION_ROTATION", "AUTH_TRANSITION", "REPLAY_SURVIVABILITY", "DEPENDENCY_ORDERING"
    description: str
    rotation_class: str = Field(default="UNKNOWN")  # "STATIC", "PER_REQUEST", "PER_SESSION", "STATE_BOUND", "UNKNOWN"
    evidence_refs: List[str] = Field(default_factory=list)
    binding_refs: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    replay_confirmed_endpoints: List[str] = Field(default_factory=list)  # ONLY endpoints with replay evidence
    confidence: float = Field(..., ge=0.0, le=1.0)
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    replay_confirmed: bool = False
    first_observed_at: datetime = Field(default_factory=datetime.utcnow)
    last_observed_at: datetime = Field(default_factory=datetime.utcnow)


class AuthConsistencyReport(BaseModel):
    """Observational report from AuthConsistencyValidator.

    Contains zero directives. Only facts and violations.
    The GovernanceKernel decides what to do.
    """

    report_id: str
    invariants: List[AuthInvariant] = Field(default_factory=list)
    evidence: List[AuthEvidence] = Field(default_factory=list)
    bindings: List[AuthBinding] = Field(default_factory=list)
    violations: List[GovernanceViolation] = Field(default_factory=list)
    auth_field_count: int = 0
    token_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ──────────────────────────────
#  Phase 4: Protocol State Machine Models
# ──────────────────────────────

class StateNode(BaseModel):
    """A single endpoint in the protocol FSM.

    NOT a generic graph node. A replay-constrained protocol state.
    """

    node_id: str
    endpoint_template: str
    method: str
    required_auth_invariants: List[str] = Field(default_factory=list)
    outgoing_edges: List[str] = Field(default_factory=list)  # edge_ids
    epistemic_state: str = Field(default=EpistemicState.OBSERVED)
    semantic_hash: Optional[str] = None


class TransitionConstraint(BaseModel):
    """A constraint that must hold for a transition to fire."""

    constraint_type: Literal["REPLAY_REQUIRED", "AUTH_REQUIRED", "ARTIFACT_REQUIRED", "STATUS_CODE"]
    description: str
    evidence_refs: List[str] = Field(default_factory=list)
    satisfied: bool = False


class TransitionEdge(BaseModel):
    """A directed transition in the protocol FSM.

    May ONLY be promoted from OBSERVED to VERIFIED via replay confirmation.
    """

    edge_id: str
    from_node: str  # node_id
    to_node: str    # node_id
    observed_count: int = 0
    replay_confirmed_count: int = 0
    failure_without_prerequisite: int = 0  # how many times to_node failed when from_node absent
    constraints: List[TransitionConstraint] = Field(default_factory=list)
    required_artifacts: List[str] = Field(default_factory=list)
    auth_dependencies: List[str] = Field(default_factory=list)
    replay_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    epistemic_state: str = Field(default=EpistemicState.OBSERVED)
    semantic_hash: Optional[str] = None

    def is_valid(self) -> bool:
        """A transition is valid only if replay-confirmed or sufficiently observed."""
        return self.replay_confirmed_count > 0 or self.replay_confidence >= 0.85


class ProtocolStateMachine(BaseModel):
    """Finite, bounded protocol state machine extracted from traces.

    NOT a generic graph. Replay-constrained FSM with bounded cardinality.
    """

    fsm_id: str
    nodes: List[StateNode] = Field(default_factory=list)
    edges: List[TransitionEdge] = Field(default_factory=list)
    max_nodes: int = 64
    max_edges: int = 256
    max_fanout: int = 8
    max_depth: int = 6
    epistemic_state: str = Field(default=EpistemicState.INFERRED)
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    def edge_count(self) -> int:
        return len(self.edges)

    def node_count(self) -> int:
        return len(self.nodes)

    def fanout(self, node_id: str) -> int:
        return sum(1 for e in self.edges if e.from_node == node_id)


# ──────────────────────────────
#  Phase 5: Semantic Quorum Models
# ──────────────────────────────

class SemanticClaim(BaseModel):
    """A single evidence-bound semantic assertion.

    Every claim MUST trace back to a specific artifact, trace, and packet.
    No free-floating semantic conclusions.
    """

    claim_id: str
    property_path: str  # e.g., "response.body.user.id.type"
    semantic_type: str   # e.g., "STRING", "UUID", "INTEGER", "BOOLEAN"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    # Evidence binding — non-negotiable
    artifact_id: str
    trace_id: str
    packet_id: str = Field(default="", description="Empty if derived from non-packet source")
    worker_id: str
    # Authority derivation
    source_epistemic_state: str
    replay_confirmed: bool = False
    provenance_chain: List[str] = Field(default_factory=list)  # artifact/trace IDs
    # Weight hierarchy enforcement
    authority_weight: float = Field(default=0.0, ge=0.0, le=1.0)


class SemanticIntersection(BaseModel):
    """The intersection of multiple claims on the same property path.

    Reduces ambiguity. Never expands semantic surface area.
    """

    intersection_id: str
    property_path: str
    intersected_type: str
    intersected_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    agreement_claim_ids: List[str] = Field(default_factory=list)
    total_authority_sum: float = Field(default=0.0, ge=0.0)
    # The lowest common denominator of source authority
    consensus_replay_confirmed: bool = False
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class SemanticConflictSet(BaseModel):
    """An explicit collection of contradictory claims.

    NEVER collapsed into blended summaries.
    Preserved for human review.
    """

    conflict_id: str
    property_path: str
    conflicting_claim_ids: List[str] = Field(default_factory=list)
    conflict_type: Literal["TYPE_MISMATCH", "PATH_DIVERGENCE", "CONFIDENCE_REGRESSION", "ENTROPY_INCREASE", "AUTHORITY_WEIGHT_COLLISION", "STATE_INCOMPATIBLE"]
    description: str
    epistemic_state: str = Field(default=EpistemicState.CONTESTED)
    max_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class SemanticQuorumReport(BaseModel):
    """Observational report from SemanticQuorum. Not a directive.

    The GovernanceKernel decides promotion.
    """

    report_id: str
    execution_id: str
    claims: List[SemanticClaim] = Field(default_factory=list)
    intersections: List[SemanticIntersection] = Field(default_factory=list)
    conflict_sets: List[SemanticConflictSet] = Field(default_factory=list)
    rejected_claims: List[SemanticClaim] = Field(default_factory=list)
    promotions: List[Dict[str, Any]] = Field(default_factory=list)
    entropy_before: float = Field(default=0.0, ge=0.0)
    entropy_after: float = Field(default=0.0, ge=0.0)
    entropy_delta: float = Field(default=0.0)
    violations: List[GovernanceViolation] = Field(default_factory=list)
    quorum_reached: bool = False
    max_depth_hit: bool = False
    bounded_truncated: bool = False
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class QuorumPromotionRule(BaseModel):
    """Deterministic, monotonic promotion rules.

    Rules are NOT learned. They are constitutional.
    """

    rule_type: Literal["PROMOTE", "DEMOTE", "REJECT", "CONTEST"]
    from_state: str
    to_state: str
    min_authority_weight: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_replay: bool = False
    requires_provenance_closure: bool = True
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    max_confidence_regrowth: float = Field(default=0.1, ge=0.0, le=1.0)


# ──────────────────────────────
#  Phase 6: Entropy Analysis Models
# ──────────────────────────────

class EntropySnapshot(BaseModel):
    """Single point-in-time entropy measurement across all dimensions.

    Deterministic and replayable. Includes input hash for reproducibility.
    """

    snapshot_id: str
    execution_id: str
    measured_at: datetime = Field(default_factory=datetime.utcnow)

    # Five entropy dimensions (0.0 = perfectly ordered, 1.0 = maximum disorder)
    structural_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    semantic_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    replay_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    temporal_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    topological_entropy: float = Field(default=0.0, ge=0.0, le=1.0)

    # Weighted composite (deterministic weights: structural=0.2, semantic=0.25, replay=0.25, temporal=0.15, topo=0.15)
    composite_entropy: float = Field(default=0.0, ge=0.0, le=1.0)

    # Fingerprint of what was measured for replay determinism
    input_hash: str = ""
    evidence_count: int = Field(default=0, ge=0)


class EntropyDelta(BaseModel):
    """Change between two entropy snapshots.

    Trend classification is deterministic based on delta thresholds.
    """

    delta_id: str
    from_snapshot_id: str
    to_snapshot_id: str

    structural_delta: float = Field(default=0.0)
    semantic_delta: float = Field(default=0.0)
    replay_delta: float = Field(default=0.0)
    temporal_delta: float = Field(default=0.0)
    topological_delta: float = Field(default=0.0)
    composite_delta: float = Field(default=0.0)

    # Deterministic trend classification
    trend: Literal["CONVERGING", "DIVERGING", "STABLE", "REGRESSING"] = "STABLE"
    regression_dimensions: List[str] = Field(default_factory=list)


class SemanticVariance(BaseModel):
    """Semantic dimension decomposition of entropy.

    Measures claim disagreement, authority fragmentation, contested growth.
    """

    disagreement_density: float = Field(default=0.0, ge=0.0, le=1.0)  # conflict_sets / total_claims
    authority_fragmentation: float = Field(default=0.0, ge=0.0, le=1.0)  # 1 - (max_authority / total_authority)
    contested_expansion_rate: float = Field(default=0.0, ge=0.0, le=1.0)  # contested_claims / total_claims
    rejected_claim_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    intersection_coverage: float = Field(default=0.0, ge=0.0, le=1.0)  # intersected_paths / total_paths


class ReplayStabilityMetric(BaseModel):
    """Replay dimension decomposition of entropy.

    Measures equivalence class consistency and drift over time.
    """

    equivalent_rate: float = Field(default=0.0, ge=0.0, le=1.0)  # STRICT + SEMANTIC / total
    non_equivalent_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    contested_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    auth_mutation_count: int = Field(default=0, ge=0)
    average_drift_score: float = Field(default=0.0, ge=0.0, le=1.0)
    replay_confirmed_edge_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class TopologicalEntropy(BaseModel):
    """FSM/Graph dimension decomposition of entropy.

    Measures branching instability and transition uncertainty.
    """

    branching_factor: float = Field(default=0.0, ge=0.0)  # edges / nodes
    fanout_variance: float = Field(default=0.0, ge=0.0)  # variance of out-degree
    unconfirmed_edge_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    node_count: int = Field(default=0, ge=0)
    edge_count: int = Field(default=0, ge=0)


class DriftSignature(BaseModel):
    """Detected regression pattern across entropy dimensions.

    Observational only. Does not prescribe action.
    """

    signature_id: str
    pattern_type: Literal[
        "STRUCTURAL_VOLATILITY",
        "SEMANTIC_FRAGMENTATION",
        "REPLAY_INSTABILITY",
        "TEMPORAL_REGRESSION",
        "TOPOLOGY_EXPLOSION",
        "CROSS_DIMENSION_CORRELATION",
    ]
    affected_dimensions: List[str] = Field(default_factory=list)
    severity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""
    first_detected: datetime = Field(default_factory=datetime.utcnow)


class ConvergenceScore(BaseModel):
    """Scalar measure of runtime convergence quality.

    1.0 = perfectly converged (all replay-confirmed, zero conflicts, zero entropy)
    0.0 = complete disorder
    """

    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_bound: float = Field(default=0.0, ge=0.0, le=1.0)
    contributing_factors: Dict[str, float] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class StabilityWindow(BaseModel):
    """Rolling window of entropy snapshots with trend analysis.

    Bounded size. Older snapshots evicted deterministically.
    """

    window_id: str
    snapshots: List[EntropySnapshot] = Field(default_factory=list)
    max_window_size: int = Field(default=32, ge=1, le=128)
    trend: Literal["IMPROVING", "DEGRADING", "OSCILLATING", "STABLE", "INSUFFICIENT_DATA"] = "INSUFFICIENT_DATA"
    average_composite_entropy: float = Field(default=0.0, ge=0.0, le=1.0)
    entropy_variance: float = Field(default=0.0, ge=0.0)
    drift_signatures: List[DriftSignature] = Field(default_factory=list)


class EntropyAnalysisReport(BaseModel):
    """Observational report from EntropyAnalysisValidator.

    The GovernanceKernel decides what to do with entropy signals.
    This module NEVER mutates runtime state.
    """

    report_id: str
    execution_id: str
    snapshot: EntropySnapshot
    delta: Optional[EntropyDelta] = None
    semantic_variance: SemanticVariance
    replay_stability: ReplayStabilityMetric
    topological_entropy: TopologicalEntropy
    convergence: ConvergenceScore
    stability_window: Optional[StabilityWindow] = None
    drift_signatures: List[DriftSignature] = Field(default_factory=list)
    violations: List[GovernanceViolation] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ─────────────────────────────────────
#  Payload Format & Content Negotiation (Gap 1: Real-World Traffic Noise)
# ─────────────────────────────────────


class PayloadFormat(str):
    """Observable payload content-type classification.

    NOT inferred from extension. Derived from Content-Type header + heuristic detection.
    """

    JSON = "application/json"
    XML = "application/xml"
    XML_TEXT = "text/xml"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    FORM_MULTIPART = "multipart/form-data"
    PROTOBUF = "application/x-protobuf"
    GRPC = "application/grpc"
    GRPC_PROTO = "application/grpc+proto"
    TEXT = "text/plain"
    HTML = "text/html"
    BINARY = "application/octet-stream"
    UNKNOWN = "unknown"


class CompressionType(str):
    """Observable compression encoding classification."""

    NONE = "none"
    GZIP = "gzip"
    BROTLI = "br"
    DEFLATE = "deflate"
    ZSTD = "zstd"
    UNKNOWN = "unknown"


class PayloadNormalization(BaseModel):
    """Normalized payload with format detection and decompression metadata.

    Raw bytes are preserved for hash integrity.
    Decompressed/formatted content is provided for downstream extraction.
    """

    raw_bytes: bytes = b""
    raw_length: int = 0
    decompressed_bytes: Optional[bytes] = None
    decompressed_length: int = 0
    format_detected: str = PayloadFormat.UNKNOWN
    format_confidence: float = 0.0  # 0.0–1.0 based on heuristic strength
    compression: str = CompressionType.NONE
    compression_detected_from: str = ""  # "content-encoding", "magic_bytes", "heuristic"
    decoding_errors: List[str] = Field(default_factory=list)
    is_parseable: bool = False
    parsed_payload: Optional[Any] = None  # dict for JSON, str for text, None for binary


class ContentNegotiationMeta(BaseModel):
    """Content-Type negotiation metadata extracted from headers.

    Captures both request Accept headers and response Content-Type.
    """

    request_accept: str = ""
    request_content_type: str = ""
    response_content_type: str = ""
    response_content_encoding: str = ""
    charset: str = "utf-8"
    boundary: Optional[str] = None  # for multipart
    transfer_encoding: str = ""


# ─────────────────────────────────────
#  Mutation-Aware Replay (Gap 2: Stateful Realities)
# ─────────────────────────────────────


class MutationClass(str):
    """Classification of endpoint mutation behavior for replay-aware equivalence.

    NOT inferred from naming. Derived from method + status code + response fingerprint.
    """

    IDEMPOTENT_READ = "IDEMPOTENT_READ"
    STATEFUL_MUTATION = "STATEFUL_MUTATION"  # POST /checkout — correct behavior changes
    DESTRUCTIVE_MUTATION = "DESTRUCTIVE_MUTATION"  # DELETE — resource gone
    NON_DETERMINISTIC = "NON_DETERMINISTIC"  # Response varies unpredictably (RNG, timestamp injection)
    REPLAY_UNSAFE = "REPLAY_UNSAFE"  # Financial, legal, irreversible — replay prohibited
    SIDE_EFFECT_BOUND = "SIDE_EFFECT_BOUND"  # Triggers async, webhook, notification
    UNKNOWN = "UNKNOWN"


class StatefulReplayClassification(str):
    """How a stateful endpoint's replay behavior should be classified.

    For stateful mutations, the replay should compare STRUCTURE, not values.
    A 409 Conflict on POST /checkout for duplicate ID is CORRECT behavior.
    """

    STATELESS = "STATELESS"  # Same request → same response
    STATE_DEPENDENT = "STATE_DEPENDENT"  # Response depends on server state
    SEQUENCE_DEPENDENT = "SEQUENCE_DEPENDENT"  # Must happen in specific order
    TIME_DEPENDENT = "TIME_DEPENDENT"  # Response varies by time (rate limits, expirations)
    UNKNOWN = "UNKNOWN"


class MutationAwareEquivalence(BaseModel):
    """Replay equivalence result for stateful endpoints.

    Distinguishes between genuine structural divergence and expected stateful behavior.
    """

    equivalence_class: str = "UNKNOWN"
    mutation_class: str = MutationClass.UNKNOWN
    stateful_class: str = StatefulReplayClassification.UNKNOWN
    is_expected_stateful_variation: bool = False
    structure_matches: bool = False  # Does the response schema match?
    status_code_matches: bool = False  # Is this the expected status for a mutation?
    semantic_field_agreement: float = 0.0  # 0.0–1.0
    description: str = ""
    violations: List[GovernanceViolation] = Field(default_factory=list)


# ─────────────────────────────────────
#  Distributed Scale Primitives (Gap 3: Scale Boundaries)
# ─────────────────────────────────────


class ValidationBoundsConfig(BaseModel):
    """Configurable bounds replacing hard-coded constants.

    Unit tests use small bounds. Production clusters configure per-shard limits.
    """

    # Provenance
    max_provenance_depth: int = 16
    max_orphaned_artifacts: int = 0

    # Replay
    max_replay_pairs: int = 512
    max_replay_depth: int = 8

    # Auth
    max_auth_invariants: int = 128
    max_evidence_per_invariant: int = 64

    # FSM
    max_fsm_nodes: int = 64
    max_fsm_edges: int = 256
    max_fsm_fanout: int = 8
    max_fsm_depth: int = 6

    # Quorum
    max_quorum_claims: int = 512
    max_quorum_intersections: int = 256
    max_quorum_conflict_sets: int = 128

    # Entropy
    max_entropy_window_size: int = 32
    max_drift_signatures: int = 64

    # Pipeline
    max_packets_per_trace: int = 1024
    max_traces_per_execution: int = 256
    max_endpoints_per_spec: int = 256

    # Shard-level
    max_endpoints_per_shard: int = 64
    max_cross_shard_edges: int = 128

    model_config = ConfigDict(frozen=True)


class ShardContext(BaseModel):
    """Distributed processing context for a single microservice horizon.

    The pipeline runs per-shard, with cross-shard edges resolved at merge time.
    """

    shard_id: str
    horizon_endpoints: List[str] = Field(default_factory=list)
    horizon_host_pattern: str = ""  # e.g., "*.api.service-a.internal"
    packet_count: int = 0
    trace_count: int = 0
    local_nodes: List[str] = Field(default_factory=list)
    local_edges: List[str] = Field(default_factory=list)
    cross_shard_edges: List[Tuple[str, str]] = Field(
        default_factory=list
    )  # (from_local, to_remote_shard)
    cross_shard_incoming: List[Tuple[str, str]] = Field(
        default_factory=list
    )  # (from_remote_shard, to_local)
    bounds: ValidationBoundsConfig = Field(default_factory=ValidationBoundsConfig)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    parent_execution_id: str = ""
