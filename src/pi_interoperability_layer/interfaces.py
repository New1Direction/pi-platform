"""Runtime Interface Governance.

Standardized worker input/output envelopes, deterministic event contracts,
replay-safe runtime messaging, provenance continuity guarantees.

No inference. No speculative messaging. No probabilistic routing.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Worker Input Envelope
# ──────────────────────────────

class WorkerInputEnvelope(BaseModel):
    """Deterministic input envelope for all governed runtimes."""

    envelope_id: str
    # Runtime target
    target_runtime: Literal[
        "pi-semantic-recon",
        "pi-semantic-validator",
        "pi-semantic-diff",
        "pi-blast-radius",
        "pi-interoperability-layer",
    ]
    # Operation to perform
    operation: Literal[
        "VALIDATE",
        "REPLAY",
        "DIFF",
        "BLAST_RADIUS",
        "REGISTER_SCHEMA",
        "MIGRATE_SCHEMA",
        "AUDIT",
    ]
    # Serialized artifact payloads
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    # Policy reference (hash or path)
    policy_ref: str = ""
    # Schema version contract required
    required_schema_version: str = ""
    # Deterministic bounds for this operation
    bounds: Dict[str, int] = Field(default_factory=dict)
    # Provenance chain of envelope origins
    provenance: List[str] = Field(default_factory=list)
    # Replay identity hash
    replay_identity_hash: str = ""
    # Sequence context for ordering
    sequence_context: Dict[str, int] = Field(default_factory=dict)
    # Strict validation flag (fail-closed)
    strict: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_identity_hash(self) -> str:
        """Deterministic identity hash of this envelope."""
        payload = self.model_dump(exclude={"replay_identity_hash", "created_at"})
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


# ──────────────────────────────
#  Worker Output Envelope
# ──────────────────────────────

class WorkerOutputEnvelope(BaseModel):
    """Deterministic output envelope from all governed runtimes."""

    envelope_id: str
    # Links to input envelope
    input_envelope_id: str
    target_runtime: str
    operation: str
    # Execution status
    status: Literal["SUCCESS", "FAILURE", "TIMEOUT", "INDETERMINATE", "REJECTED"]
    # Result payload
    result: Dict[str, Any] = Field(default_factory=dict)
    # Violations detected
    violations: List[Dict[str, Any]] = Field(default_factory=list)
    # Evidence count
    evidence_count: int = 0
    # Replay verification status
    replay_verified: bool = False
    replay_verification_hash: str = ""
    # Output identity hash
    output_hash: str = ""
    # Execution metadata
    execution_time_ms: int = 0
    # Provenance continuation
    provenance: List[str] = Field(default_factory=list)
    # Sequence context preserved
    sequence_context: Dict[str, int] = Field(default_factory=dict)
    # Strict mode preserved
    strict: bool = True
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_output_hash(self) -> str:
        """Deterministic output hash for verification."""
        payload = self.model_dump(exclude={"output_hash", "completed_at"})
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


# ──────────────────────────────
#  Runtime Message Contract
# ──────────────────────────────

class RuntimeMessage(BaseModel):
    """Deterministic runtime-to-runtime message with provenance continuity."""

    message_id: str
    message_type: Literal[
        "ARTIFACT_HANDOFF",
        "VALIDATION_REQUEST",
        "VALIDATION_RESPONSE",
        "REPLAY_REQUEST",
        "REPLAY_RESPONSE",
        "DIFF_REQUEST",
        "DIFF_RESPONSE",
        "BLAST_RADIUS_REQUEST",
        "BLAST_RADIUS_RESPONSE",
        "SCHEMA_MIGRATION_NOTICE",
        "POLICY_UPDATE",
        "AUDIT_REQUEST",
        "AUDIT_RESPONSE",
    ]
    source_runtime: str
    target_runtime: str
    # Payload envelope (WorkerInputEnvelope or WorkerOutputEnvelope serialized)
    envelope: Dict[str, Any] = Field(default_factory=dict)
    # Provenance chain: list of message_ids that led to this message
    provenance_chain: List[str] = Field(default_factory=list)
    # Hash of the provenance chain for integrity
    provenance_hash: str = ""
    # Replay-safe flag
    replay_safe: bool = False
    # Sequence number in the inter-runtime message log
    sequence_number: int = Field(..., ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_provenance_hash(self) -> str:
        """Deterministic hash of the provenance chain."""
        return hashlib.sha256(
            json.dumps(self.provenance_chain, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


# ──────────────────────────────
#  Provenance Continuity
# ──────────────────────────────

class ProvenanceChain(BaseModel):
    """Immutable provenance chain for cross-runtime artifact flow."""

    chain_id: str
    # Ordered list of runtime identifiers that touched this artifact
    runtime_sequence: List[str] = Field(default_factory=list)
    # Ordered list of envelope IDs
    envelope_sequence: List[str] = Field(default_factory=list)
    # Ordered list of artifact fingerprints
    artifact_fingerprints: List[str] = Field(default_factory=list)
    # Chain hash
    chain_hash: str = ""
    model_config = {"frozen": True}

    def append_step(
        self,
        runtime: str,
        envelope_id: str,
        artifact_fingerprint: str,
    ) -> "ProvenanceChain":
        """Append a provenance step and return a new chain (immutable update)."""
        new_runtime = list(self.runtime_sequence) + [runtime]
        new_envelope = list(self.envelope_sequence) + [envelope_id]
        new_fp = list(self.artifact_fingerprints) + [artifact_fingerprint]
        combined = "".join(new_runtime + new_envelope + new_fp)
        new_hash = hashlib.sha256(combined.encode()).hexdigest()
        return ProvenanceChain(
            chain_id=self.chain_id,
            runtime_sequence=new_runtime,
            envelope_sequence=new_envelope,
            artifact_fingerprints=new_fp,
            chain_hash=new_hash,
        )

    def verify_continuity(self) -> bool:
        """Verify that the chain hash matches recomputed state."""
        combined = "".join(
            self.runtime_sequence + self.envelope_sequence + self.artifact_fingerprints
        )
        expected = hashlib.sha256(combined.encode()).hexdigest()
        return self.chain_hash == expected


# ──────────────────────────────
#  Replay-Safe Runtime Messaging
# ──────────────────────────────

class ReplaySafeRouter(BaseModel):
    """Deterministic router for replay-safe runtime messaging."""

    # Allowed routing table: source -> list of allowed targets
    allowed_routes: Dict[str, List[str]] = Field(default_factory=dict)
    # Replay-safe routes only
    replay_safe_routes: Dict[str, List[str]] = Field(default_factory=dict)
    model_config = {"frozen": True}

    def route(
        self,
        message: RuntimeMessage,
    ) -> Literal["ALLOWED", "FORBIDDEN", "REQUIRES_REPLAY_VERIFICATION"]:
        """Deterministic routing decision."""
        allowed = self.allowed_routes.get(message.source_runtime, [])
        if message.target_runtime not in allowed:
            return "FORBIDDEN"
        safe = self.replay_safe_routes.get(message.source_runtime, [])
        if message.target_runtime in safe:
            return "ALLOWED"
        return "REQUIRES_REPLAY_VERIFICATION"

    def is_replay_safe(self, source: str, target: str) -> bool:
        return target in self.replay_safe_routes.get(source, [])
