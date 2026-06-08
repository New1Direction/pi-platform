"""Event-Sourced Execution Layer.

Immutable event log format, deterministic replay ledger, ordered execution guarantees,
replay identity hashing, distributed replay coordination.

No inference. No probabilistic state. No speculative promotion.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Event Record Primitives
# ──────────────────────────────


class EventRecord(BaseModel):
    """Immutable event in the execution log."""

    event_id: str
    event_type: Literal[
        "ARTIFACT_RECEIVED",
        "VALIDATION_STARTED",
        "VALIDATION_PASSED",
        "VALIDATION_FAILED",
        "VIOLATION_DETECTED",
        "REPLAY_EXECUTED",
        "REPLAY_MISMATCH",
        "POLICY_LOADED",
        "POLICY_VIOLATION",
        "SCHEMA_REGISTERED",
        "SCHEMA_MIGRATION",
        "BLAST_RADIUS_COMPUTED",
        "MUTATION_AUTHORIZED",
        "MUTATION_REJECTED",
        "WORKER_SPAWNED",
        "WORKER_COMPLETED",
    ]
    # Deterministic event payload
    payload: Dict[str, Any] = Field(default_factory=dict)
    # Ordered sequence number (strictly monotonic within a ledger)
    sequence_number: int = Field(default=0, ge=0)
    # Hash of the previous event (append-only chain)
    previous_hash: str = ""
    # Identity hash of this event
    event_hash: str = ""
    # Runtime that emitted this event
    emitted_by: str = ""
    # UTC timestamp
    emitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Replay evidence references
    replay_evidence: List[str] = Field(default_factory=list)
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        """Deterministic identity hash for this event.

        Content-addressed: hashes only the logical content + causal/structural
        position (sequence_number + previous_hash chain). The wall-clock
        `emitted_at` is excluded so the same logical event reproduces the same
        hash across runs; it is still STORED/RETURNED as event metadata.
        """
        payload_bytes = canonical_event_payload(self.payload)
        data = {
            "event_type": self.event_type,
            "sequence_number": self.sequence_number,
            "previous_hash": self.previous_hash,
            "payload": payload_bytes,
            "emitted_by": self.emitted_by,
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ──────────────────────────────
#  Replay Ledger
# ──────────────────────────────


class ReplayLedger(BaseModel):
    """Append-only deterministic replay ledger.

    Ordered execution guarantees:
      * sequence_number is strictly monotonic
      * previous_hash chains events
      * ledger_hash is recomputed after every append
    """

    ledger_id: str
    events: List[EventRecord] = Field(default_factory=list)
    ledger_hash: str = ""
    first_sequence: int = 0
    last_sequence: int = 0
    event_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None

    def append(self, event: EventRecord) -> EventRecord:
        """Append an event with chain hashing and sequence assignment."""
        prev_hash = self.events[-1].event_hash if self.events else ""
        seq = self.last_sequence + 1

        # Build event with chain linkage
        linked_event = EventRecord(
            event_id=event.event_id,
            event_type=event.event_type,
            payload=event.payload,
            sequence_number=seq,
            previous_hash=prev_hash,
            event_hash="",  # computed below
            emitted_by=event.emitted_by,
            emitted_at=event.emitted_at,
            replay_evidence=event.replay_evidence,
        )
        event_hash = linked_event.compute_hash()
        linked_event = linked_event.model_copy(update={"event_hash": event_hash})

        self.events.append(linked_event)
        self.last_sequence = seq
        self.event_count = len(self.events)
        self._rehash()
        return linked_event

    def _rehash(self) -> None:
        """Recompute ledger hash from all event hashes."""
        combined = "".join(e.event_hash for e in self.events)
        self.ledger_hash = hashlib.sha256(combined.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify chain integrity: every event's previous_hash matches prior ledger state."""
        running_hash = ""
        for i, event in enumerate(self.events):
            expected_seq = self.first_sequence + i
            if event.sequence_number != expected_seq:
                return False
            if event.previous_hash != running_hash:
                return False
            recomputed = event.compute_hash()
            if event.event_hash != recomputed:
                return False
            running_hash = event.event_hash
        return True

    def replay_events(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> List[EventRecord]:
        """Deterministic replay slice."""
        start = from_sequence or self.first_sequence
        end = to_sequence or self.last_sequence
        return [e for e in self.events if start <= e.sequence_number <= end]

    def get_event(self, event_id: str) -> Optional[EventRecord]:
        for e in self.events:
            if e.event_id == event_id:
                return e
        return None


# ──────────────────────────────
#  Execution Engine
# ──────────────────────────────


class ExecutionEngine(BaseModel):
    """Deterministic execution engine with event sourcing and replay."""

    engine_id: str
    active_ledgers: Dict[str, ReplayLedger] = Field(default_factory=dict)
    completed_ledgers: Dict[str, ReplayLedger] = Field(default_factory=dict)
    max_events_per_ledger: int = Field(default=10000, ge=1)
    max_ledger_count: int = Field(default=128, ge=1)
    model_config = {"frozen": True}

    def open_ledger(self, ledger_id: str) -> ReplayLedger:
        """Open a new replay ledger."""
        if ledger_id in self.active_ledgers:
            raise ValueError(f"Ledger {ledger_id} already open")
        if len(self.active_ledgers) >= self.max_ledger_count:
            raise ValueError("Max ledger count exceeded")
        ledger = ReplayLedger(ledger_id=ledger_id, first_sequence=1, last_sequence=0)
        self.active_ledgers[ledger_id] = ledger
        return ledger

    def emit(
        self,
        ledger_id: str,
        event_type: str,
        payload: Dict[str, Any],
        emitted_by: str,
        replay_evidence: Optional[List[str]] = None,
    ) -> EventRecord:
        """Emit an event into an active ledger."""
        ledger = self.active_ledgers.get(ledger_id)
        if not ledger:
            raise ValueError(f"Ledger {ledger_id} not open")
        if ledger.event_count >= self.max_events_per_ledger:
            raise ValueError(f"Ledger {ledger_id} event limit exceeded")

        event = EventRecord(
            event_id=f"evt_{ledger_id}_{ledger.last_sequence + 1}",
            event_type=event_type,  # type: ignore[arg-type]
            payload=payload,
            emitted_by=emitted_by,
            replay_evidence=replay_evidence or [],
        )
        return ledger.append(event)

    def close_ledger(self, ledger_id: str) -> ReplayLedger:
        """Close an active ledger and move it to completed."""
        ledger = self.active_ledgers.pop(ledger_id, None)
        if not ledger:
            raise ValueError(f"Ledger {ledger_id} not open")
        closed = ledger.model_copy(update={"closed_at": datetime.now(timezone.utc)})
        self.completed_ledgers[ledger_id] = closed
        return closed

    def replay_ledger(
        self,
        ledger_id: str,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> List[EventRecord]:
        """Deterministic replay of a completed ledger."""
        ledger = self.completed_ledgers.get(ledger_id)
        if not ledger:
            raise ValueError(f"Ledger {ledger_id} not found")
        return ledger.replay_events(from_sequence, to_sequence)

    def verify_ledger(self, ledger_id: str) -> bool:
        """Verify ledger integrity."""
        ledger = self.completed_ledgers.get(ledger_id)
        if not ledger:
            return False
        return ledger.verify_integrity()


# ──────────────────────────────
#  Deterministic Payload Canonicalization
# ──────────────────────────────


def canonical_event_payload(payload: Dict[str, Any]) -> str:
    """Canonical deterministic JSON for event payloads."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
