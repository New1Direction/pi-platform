"""PI Console Boundary Schemas.

Canonical JSON schema definitions for the ONLY communication path between
PI Console (Layer 4, human interface) and PI Core (Layers 1-3, deterministic
execution fabric).

No LLM inference in this module. No probabilistic fields. No speculative types.
All structures are frozen, deterministic, and strictly validated.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ──────────────────────────────
#  ExplicitCompositionRequest
#  The ONE canonical request type
# ──────────────────────────────

class CompositionNode(BaseModel):
    """A single node in the composition DAG."""

    node_id: str = Field(..., description="Unique identifier within this composition")
    runtime: Literal[
        "pi-semantic-recon",
        "pi-semantic-validator",
        "pi-semantic-diff",
        "pi-blast-radius",
        "pi-interoperability-layer",
        "pi-extension-governor",
        "pi-catalog-integration",
    ] = Field(..., description="Target runtime for this node")
    operation: Literal[
        "VALIDATE",
        "REPLAY",
        "DIFF",
        "BLAST_RADIUS",
        "REGISTER_SCHEMA",
        "MIGRATE_SCHEMA",
        "AUDIT",
        "INGEST",
        "CLASSIFY",
        "POLICY_GATE",
        "SANDBOX",
        "NORMALIZE",
        "DEPENDENCY_EXPAND",
        "COMPOSE",
    ] = Field(..., description="Operation to execute")
    # Strict artifact payload (dict must be serializable)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    # Schema version contract required for this node
    required_schema_version: str = ""
    # Deterministic bounds (max_nodes, max_depth, max_fanout, etc.)
    bounds: Dict[str, int] = Field(default_factory=dict)
    # Dependencies: node_ids that must complete before this node
    dependencies: List[str] = Field(default_factory=list)
    model_config = {"frozen": True}

    @field_validator("artifacts")
    @classmethod
    def _artifacts_serializable(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Ensure every artifact can be deterministically serialized
        for artifact in v:
            try:
                json.dumps(artifact, sort_keys=True, separators=(",", ":"), default=str)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Artifact not JSON-serializable: {exc}") from exc
        return v


class CompositionEdge(BaseModel):
    """A directed edge between composition nodes."""

    source: str = Field(..., description="Source node_id")
    target: str = Field(..., description="Target node_id")
    edge_type: Literal["SEQUENTIAL", "PARALLEL", "CONDITIONAL", "FAN_OUT", "FAN_IN"] = "SEQUENTIAL"
    condition: Optional[str] = None  # Only for CONDITIONAL edges; must be a deterministic expression
    model_config = {"frozen": True}


class ExplicitCompositionRequest(BaseModel):
    """The ONLY request type accepted by PI Core from PI Console.

    Every field is deterministic, versioned, and strictly validated.
    No natural language. No probabilistic parameters. No speculative execution.
    """

    request_id: str = Field(default_factory=lambda: f"ecr_{uuid.uuid4().hex[:16]}")
    tenant_id: str = Field(..., description="Tenant scope for multi-tenant isolation")
    console_session_id: str = Field(..., description="PI Console session that originated this request")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Composition DAG
    nodes: List[CompositionNode] = Field(..., min_length=1, description="DAG nodes to execute")
    edges: List[CompositionEdge] = Field(default_factory=list, description="DAG edges defining execution order")

    # Global policy and schema references
    global_policy_ref: str = Field(default="", description="Policy hash or identifier")
    global_schema_version: str = Field(default="", description="Global schema version contract")

    # Deterministic global bounds
    global_bounds: Dict[str, int] = Field(
        default_factory=lambda: {
            "max_total_nodes": 64,
            "max_depth": 8,
            "max_fanout": 16,
            "max_execution_time_ms": 300_000,
        },
        description="Global execution bounds",
    )

    # Simulation-only flag: if true, core runs simulation and returns report without mutating state
    simulation_only: bool = Field(default=True, description="If true, only simulate — do not execute")

    # Audit trail: exact JSON of user approval state
    approved_by_user: bool = Field(default=False, description="Whether the user explicitly approved this request")
    approval_timestamp: Optional[datetime] = Field(default=None)

    # Strict validation flag (fail-closed)
    strict: bool = Field(default=True)

    # Request fingerprint (computed deterministically)
    request_hash: str = Field(default="", description="SHA-256 of canonical request payload")

    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        """Deterministic SHA-256 of this request."""
        payload = self.model_dump(
            exclude={"request_hash", "created_at", "approval_timestamp"}
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def with_hash(self) -> "ExplicitCompositionRequest":
        """Return a new request with computed hash populated."""
        h = self.compute_hash()
        return self.model_copy(update={"request_hash": h})


# ──────────────────────────────
#  Tool Request/Response Schemas
#  (OpenAPI-exposed operations)
# ──────────────────────────────

class SubmitCompositionRequest(BaseModel):
    """Tool request: submit_explicit_composition_request"""

    composition: ExplicitCompositionRequest = Field(..., description="The explicit composition to submit")
    user_confirmation: bool = Field(..., description="User must explicitly confirm before submission")


class SubmitCompositionResponse(BaseModel):
    """Tool response: submit_explicit_composition_request"""

    request_id: str
    accepted: bool
    status: Literal["ACCEPTED", "REJECTED", "QUEUED", "SIMULATING"]
    message: str
    core_ledger_id: Optional[str] = None
    estimated_execution_time_ms: int = 0


class SimulateCompositionRequest(BaseModel):
    """Tool request: simulate_composition"""

    composition: ExplicitCompositionRequest = Field(..., description="The explicit composition to simulate")


class SimulationReport(BaseModel):
    """Deterministic simulation report before any execution."""

    report_id: str = Field(default_factory=lambda: f"sim_{uuid.uuid4().hex[:16]}")
    request_id: str
    tenant_id: str
    # Structural validation
    dag_valid: bool = False
    dag_errors: List[str] = Field(default_factory=list)
    # Bounds check
    bounds_respected: bool = False
    bounds_violations: List[str] = Field(default_factory=list)
    # Policy check
    policy_violations: List[str] = Field(default_factory=list)
    # Blast radius preview
    estimated_blast_radius: Dict[str, Any] = Field(default_factory=dict)
    # Execution plan
    execution_plan: List[str] = Field(default_factory=list)
    # Risk summary
    risk_level: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    risk_details: List[str] = Field(default_factory=list)
    # Replay-safe verification
    replay_safe: bool = False
    replay_verification_hash: str = ""
    # Deterministic report hash
    report_hash: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = self.model_dump(exclude={"report_hash", "generated_at"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class SimulateCompositionResponse(BaseModel):
    """Tool response: simulate_composition"""

    report: SimulationReport
    can_execute: bool  # False if simulation shows any blocking issue


class GetExecutionReplayRequest(BaseModel):
    """Tool request: get_execution_replay"""

    ledger_id: str = Field(..., description="Ledger ID from a prior execution")
    from_sequence: Optional[int] = None
    to_sequence: Optional[int] = None


class ExecutionReplayEvent(BaseModel):
    """A single event in an execution replay."""

    sequence_number: int
    event_type: str
    emitted_by: str
    emitted_at: str
    event_hash: str
    previous_hash: str
    payload_summary: Dict[str, Any] = Field(default_factory=dict)


class GetExecutionReplayResponse(BaseModel):
    """Tool response: get_execution_replay"""

    ledger_id: str
    events: List[ExecutionReplayEvent]
    integrity_verified: bool
    total_events: int


class ListMarketplaceCapabilitiesRequest(BaseModel):
    """Tool request: list_marketplace_capabilities"""

    tenant_id: str
    filter_runtime: Optional[str] = None
    filter_operation: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class MarketplaceCapability(BaseModel):
    """A capability available in the marketplace."""

    capability_id: str
    runtime: str
    operation: str
    description: str
    schema_version: str
    trust_tier: Literal["UNVERIFIED", "VERIFIED", "AUDITED", "GOVERNED"] = "UNVERIFIED"
    compatibility_tags: List[str] = Field(default_factory=list)
    deterministic_bounds: Dict[str, int] = Field(default_factory=dict)


class ListMarketplaceCapabilitiesResponse(BaseModel):
    """Tool response: list_marketplace_capabilities"""

    capabilities: List[MarketplaceCapability]
    total: int
    limit: int
    offset: int


class GetTenantQuotaStatusRequest(BaseModel):
    """Tool request: get_tenant_quota_status"""

    tenant_id: str


class TenantQuotaStatus(BaseModel):
    """Current quota consumption for a tenant."""

    tenant_id: str
    compositions_submitted: int = 0
    compositions_executed: int = 0
    simulations_run: int = 0
    max_compositions_per_hour: int = 100
    max_simulations_per_hour: int = 500
    max_nodes_per_composition: int = 64
    current_hour_compositions: int = 0
    current_hour_simulations: int = 0
    quota_exceeded: bool = False


class GetTenantQuotaStatusResponse(BaseModel):
    """Tool response: get_tenant_quota_status"""

    quota: TenantQuotaStatus


class AuditLogEntry(BaseModel):
    """A single entry in the PI Console audit log."""

    entry_id: str = Field(default_factory=lambda: f"aud_{uuid.uuid4().hex[:16]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    console_session_id: str
    request_id: str
    action: Literal[
        "COMPOSITION_SUBMITTED",
        "COMPOSITION_SIMULATED",
        "COMPOSITION_APPROVED",
        "COMPOSITION_REJECTED",
        "EXECUTION_REPLAY_VIEWED",
        "MARKETPLACE_QUERIED",
        "QUOTA_CHECKED",
        "DAG_VISUALIZED",
        "CHAT_MESSAGE_SENT",
    ]
    # Exact structured request sent (or received) — fully logged
    structured_request: Dict[str, Any] = Field(default_factory=dict)
    response_status: str = ""
    user_ip: str = ""
    model_config = {"frozen": True}


class GetAuditLogRequest(BaseModel):
    """Tool request: get_audit_log"""

    tenant_id: str
    console_session_id: Optional[str] = None
    action_filter: Optional[str] = None
    from_timestamp: Optional[datetime] = None
    to_timestamp: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class GetAuditLogResponse(BaseModel):
    """Tool response: get_audit_log"""

    entries: List[AuditLogEntry]
    total: int


class GetCompatibilityGraphRequest(BaseModel):
    """Tool request: get_compatibility_graph"""

    tenant_id: str
    runtime_filter: Optional[str] = None


class CompatibilityNode(BaseModel):
    """Node in the compatibility graph."""

    capability_id: str
    runtime: str
    trust_tier: str


class CompatibilityEdge(BaseModel):
    """Edge in the compatibility graph."""

    source_capability: str
    target_capability: str
    compatible: bool
    reason: str = ""


class GetCompatibilityGraphResponse(BaseModel):
    """Tool response: get_compatibility_graph"""

    nodes: List[CompatibilityNode]
    edges: List[CompatibilityEdge]


class ChatTranslationRequest(BaseModel):
    """Internal console request: translate natural language → ExplicitCompositionRequest.

    This is ONLY used inside the PI Console boundary. It NEVER crosses into the core.
    The LLM (if configured) only populates this structure; validation happens before
    any core submission.
    """

    console_session_id: str
    tenant_id: str
    user_message: str = Field(..., max_length=4000)
    # Optional: prior context (last N approved requests)
    context_request_ids: List[str] = Field(default_factory=list)


class ChatTranslationResponse(BaseModel):
    """Internal console response: proposed ExplicitCompositionRequest or rejection."""

    proposed_composition: Optional[ExplicitCompositionRequest] = None
    translation_valid: bool = False
    validation_errors: List[str] = Field(default_factory=list)
    explanation: str = ""  # Human-readable explanation of the proposed composition
    requires_user_approval: bool = True


# ──────────────────────────────
#  Console Session State
#  (Ephemeral, tenant-scoped)
# ──────────────────────────────

class ConsoleSession(BaseModel):
    """Ephemeral session state for a PI Console user."""

    session_id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:16]}")
    tenant_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_request_ids: List[str] = Field(default_factory=list)
    rejected_request_ids: List[str] = Field(default_factory=list)
    # LLM configuration (optional — can be disabled entirely)
    llm_enabled: bool = False
    llm_provider: Optional[str] = None
    model_config = {"frozen": False}  # Session state is mutable by design


class ConsoleHealth(BaseModel):
    """Health status of the PI Console layer."""

    status: Literal["HEALTHY", "DEGRADED", "UNHEALTHY"] = "HEALTHY"
    core_reachable: bool = False
    ledger_storage_reachable: bool = False
    schema_registry_reachable: bool = False
    console_uptime_seconds: int = 0
    active_sessions: int = 0
    version: str = "4.0.0"
