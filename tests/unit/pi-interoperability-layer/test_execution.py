"""Tests for event-sourced execution layer."""

from __future__ import annotations

import pytest

from pi_interoperability_layer.execution import (
    EventRecord,
    ExecutionEngine,
    ReplayLedger,
    canonical_event_payload,
)


def test_event_record_compute_hash_determinism() -> None:
    e1 = EventRecord(
        event_id="e1",
        event_type="ARTIFACT_RECEIVED",
        payload={"a": 1},
        sequence_number=1,
        previous_hash="",
        emitted_by="test",
    )
    h1 = e1.compute_hash()
    h2 = e1.compute_hash()
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_replay_ledger_append_and_sequence() -> None:
    ledger = ReplayLedger(ledger_id="L1", first_sequence=1, last_sequence=0)
    event = EventRecord(
        event_id="e1",
        event_type="VALIDATION_STARTED",
        payload={},
        emitted_by="test",
    )
    appended = ledger.append(event)
    assert appended.sequence_number == 1
    assert appended.previous_hash == ""
    assert appended.event_hash != ""
    assert ledger.last_sequence == 1
    assert ledger.event_count == 1
    assert ledger.ledger_hash != ""


def test_replay_ledger_chain_integrity() -> None:
    ledger = ReplayLedger(ledger_id="L1", first_sequence=1, last_sequence=0)
    for i in range(3):
        event = EventRecord(
            event_id=f"e{i}",
            event_type="VALIDATION_PASSED",
            payload={"idx": i},
            emitted_by="test",
        )
        ledger.append(event)
    assert ledger.verify_integrity() is True
    assert len(ledger.events) == 3
    # Sequence numbers must be 1,2,3
    assert [e.sequence_number for e in ledger.events] == [1, 2, 3]


def test_replay_ledger_replay_slice() -> None:
    ledger = ReplayLedger(ledger_id="L1", first_sequence=1, last_sequence=0)
    for i in range(5):
        event = EventRecord(
            event_id=f"e{i}",
            event_type="VALIDATION_PASSED",
            payload={"idx": i},
            emitted_by="test",
        )
        ledger.append(event)
    slice_events = ledger.replay_events(from_sequence=2, to_sequence=4)
    assert len(slice_events) == 3
    assert [e.sequence_number for e in slice_events] == [2, 3, 4]


def test_execution_engine_open_emit_close() -> None:
    engine = ExecutionEngine(engine_id="eng1")
    engine.open_ledger("L1")
    emitted = engine.emit(
        ledger_id="L1",
        event_type="ARTIFACT_RECEIVED",
        payload={"artifact_id": "a1"},
        emitted_by="recon",
    )
    assert emitted.sequence_number == 1
    assert emitted.previous_hash == ""
    closed = engine.close_ledger("L1")
    assert closed.ledger_id == "L1"
    assert closed.closed_at is not None
    assert "L1" in engine.completed_ledgers


def test_execution_engine_max_events_bound() -> None:
    engine = ExecutionEngine(engine_id="eng1", max_events_per_ledger=2)
    engine.open_ledger("L1")
    engine.emit("L1", "ARTIFACT_RECEIVED", {"i": 1}, "test")
    engine.emit("L1", "ARTIFACT_RECEIVED", {"i": 2}, "test")
    with pytest.raises(ValueError, match="event limit exceeded"):
        engine.emit("L1", "ARTIFACT_RECEIVED", {"i": 3}, "test")


def test_execution_engine_verify_ledger() -> None:
    engine = ExecutionEngine(engine_id="eng1")
    engine.open_ledger("L1")
    engine.emit("L1", "ARTIFACT_RECEIVED", {"i": 1}, "test")
    engine.close_ledger("L1")
    assert engine.verify_ledger("L1") is True


def test_canonical_event_payload() -> None:
    payload = {"z": 1, "a": 2}
    s1 = canonical_event_payload(payload)
    s2 = canonical_event_payload({"a": 2, "z": 1})
    assert s1 == s2
