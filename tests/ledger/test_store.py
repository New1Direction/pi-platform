from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.pi_runtime.ledger.models import AgentState, LedgerEntry
from src.pi_runtime.ledger.store import LedgerStore
from src.pi_runtime.ledger.validator import validator


def create_valid_entry():
    return LedgerEntry(
        task_id=uuid4(),
        actor_id="network-grpc-v1",
        from_state=AgentState.UNASSIGNED,
        to_state=AgentState.OBSERVED,
        evidence_hash="a" * 64,
        timestamp=datetime.now(timezone.utc),
        entropy_delta=-1,
    )


def test_ledger_store_can_append_and_read():
    store = LedgerStore(":memory:")
    entry = create_valid_entry()

    assert store.append(entry) is True
    retrieved = store.get_by_task_id(entry.task_id)

    assert retrieved is not None
    assert retrieved.task_id == entry.task_id
    assert retrieved.actor_id == "network-grpc-v1"
    assert retrieved.to_state == AgentState.OBSERVED


def test_ledger_store_enforces_append_only():
    store = LedgerStore(":memory:")
    entry = create_valid_entry()
    store.append(entry)

    # Attempting UPDATE should be blocked by DB trigger
    with pytest.raises(Exception, match="forbidden|UPDATE|append-only"):
        store._conn.execute("UPDATE ledger_entries SET actor_id = 'hacked' WHERE task_id = ?", (str(entry.task_id),))


def test_ledger_store_verify_integrity():
    store = LedgerStore(":memory:")
    assert store.verify_integrity() is True


def test_invalid_transition_detected_by_validator():
    """Store is intentionally dumb append-only; validation lives in the
    validator and is enforced by the orchestrator at read time."""
    bad_entry = LedgerEntry(
        task_id=uuid4(),
        actor_id="test",
        from_state=AgentState.COMMITTED,
        to_state=AgentState.OBSERVED,  # invalid jump
        evidence_hash="b" * 64,
        timestamp=datetime.now(timezone.utc),
        entropy_delta=0,
    )
    result = validator.validate_transition(bad_entry)
    assert result.is_valid is False
    assert "Invalid state transition" in result.reason
