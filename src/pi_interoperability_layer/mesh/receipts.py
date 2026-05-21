"""Execution Receipts and Orchestration Ledger.

Immutable execution receipts with chain hashing.
Append-only orchestration ledger with phase boundaries.

No inference. No LLM calls. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ExecutionReceipt(BaseModel):
    """Immutable record of a single worker execution."""

    receipt_id: str = Field(default_factory=lambda: f"rcpt_{uuid.uuid4().hex[:16]}")
    worker_class: str
    worker_id: str
    phase: str
    input_slot_ids: List[str] = Field(default_factory=list)
    output_slot_ids: List[str] = Field(default_factory=list)
    status: str = "PENDING"  # PENDING, SUCCESS, FAIL, TIMEOUT, PANIC, SCHEMA_MISMATCH, REPLAY_MISMATCH, RESOURCE_EXCEEDED
    status_detail: str = ""
    determinism_proof: str = ""  # hash proving deterministic output
    resource_usage: Dict[str, float] = Field(default_factory=dict)  # e.g. {"cpu_ms": 12.3, "memory_mb": 45.6}
    previous_receipt_hash: str = ""
    receipt_hash: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": False}

    def compute_hash(self) -> str:
        payload = {
            "receipt_id": self.receipt_id,
            "worker_class": self.worker_class,
            "worker_id": self.worker_id,
            "phase": self.phase,
            "input_slot_ids": sorted(self.input_slot_ids),
            "output_slot_ids": sorted(self.output_slot_ids),
            "status": self.status,
            "status_detail": self.status_detail,
            "determinism_proof": self.determinism_proof,
            "resource_usage": self.resource_usage,
            "previous_receipt_hash": self.previous_receipt_hash,
            "timestamp": self.timestamp.isoformat(),
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(payload_bytes).hexdigest()


class PhaseBoundaryReceipt(BaseModel):
    """Receipt marking the end of a phase with merged outputs."""

    boundary_id: str = Field(default_factory=lambda: f"bnd_{uuid.uuid4().hex[:16]}")
    phase: str
    worker_receipt_ids: List[str] = Field(default_factory=list)
    merged_output_slot_id: Optional[str] = None
    phase_status: str = "PENDING"  # PENDING, SUCCESS, FAIL, BLOCKED
    previous_boundary_hash: str = ""
    boundary_hash: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": False}

    def compute_hash(self) -> str:
        payload = {
            "boundary_id": self.boundary_id,
            "phase": self.phase,
            "worker_receipt_ids": sorted(self.worker_receipt_ids),
            "merged_output_slot_id": self.merged_output_slot_id,
            "phase_status": self.phase_status,
            "previous_boundary_hash": self.previous_boundary_hash,
            "timestamp": self.timestamp.isoformat(),
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(payload_bytes).hexdigest()


class OrchestrationLedger(BaseModel):
    """Append-only ledger of all execution receipts and phase boundaries."""

    ledger_id: str = Field(default_factory=lambda: f"ledger_{uuid.uuid4().hex[:16]}")
    pipeline_name: str = "default"
    receipts: List[ExecutionReceipt] = Field(default_factory=list)
    boundaries: List[PhaseBoundaryReceipt] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None
    model_config = {"frozen": False}

    def append_receipt(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        prev = self.receipts[-1].receipt_hash if self.receipts else ""
        receipt = receipt.model_copy(update={"previous_receipt_hash": prev})
        receipt = receipt.model_copy(update={"receipt_hash": receipt.compute_hash()})
        self.receipts.append(receipt)
        return receipt

    def append_boundary(self, boundary: PhaseBoundaryReceipt) -> PhaseBoundaryReceipt:
        prev = self.boundaries[-1].boundary_hash if self.boundaries else ""
        boundary = boundary.model_copy(update={"previous_boundary_hash": prev})
        boundary = boundary.model_copy(update={"boundary_hash": boundary.compute_hash()})
        self.boundaries.append(boundary)
        return boundary

    def verify_chain(self) -> bool:
        for i, r in enumerate(self.receipts):
            expected_prev = self.receipts[i - 1].receipt_hash if i > 0 else ""
            if r.previous_receipt_hash != expected_prev:
                return False
            if r.compute_hash() != r.receipt_hash:
                return False
        for i, b in enumerate(self.boundaries):
            expected_prev = self.boundaries[i - 1].boundary_hash if i > 0 else ""
            if b.previous_boundary_hash != expected_prev:
                return False
            if b.compute_hash() != b.boundary_hash:
                return False
        return True

    def last_boundary_for_phase(self, phase: str) -> Optional[PhaseBoundaryReceipt]:
        for b in reversed(self.boundaries):
            if b.phase == phase:
                return b
        return None

    def receipts_for_phase(self, phase: str) -> List[ExecutionReceipt]:
        return [r for r in self.receipts if r.phase == phase]

    def close(self) -> None:
        self.closed_at = datetime.now(timezone.utc)
