from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.pi_runtime.ledger.models import AgentState, LedgerEntry


def test_agentstate_is_strenum():
    assert AgentState.OBSERVED == "OBSERVED"
    assert isinstance(AgentState.OBSERVED, str)
    assert AgentState("INFERRED") == AgentState.INFERRED


def test_ledger_entry_is_frozen():
    entry = LedgerEntry(
        task_id=uuid4(),
        actor_id="network-grpc-v1",
        from_state=AgentState.UNASSIGNED,
        to_state=AgentState.OBSERVED,
        evidence_hash="a" * 64,
        timestamp=datetime.now(timezone.utc),
        entropy_delta=-1,
    )

    # Pydantic v2 frozen models raise ValidationError, not plain TypeError
    with pytest.raises(Exception):
        entry.task_id = uuid4()


def test_ledger_entry_canonical_serialization():
    task_id = uuid4()
    entry = LedgerEntry(
        task_id=task_id,
        actor_id="binary-analyst-v1",
        from_state=AgentState.UNASSIGNED,
        to_state=AgentState.INFERRED,
        evidence_hash="b" * 64,
        timestamp=datetime(2026, 5, 22, 17, 0, 0, tzinfo=timezone.utc),
        entropy_delta=0,
    )

    data = entry.model_dump(mode="json")
    assert data["from_state"] == "UNASSIGNED"
    assert data["to_state"] == "INFERRED"
    assert data["evidence_hash"] == ("b" * 64).lower()
    assert "timestamp" in data
    # Transition from UNASSIGNED to INFERRED is not in our simple map yet
    # We will expand the state machine in a later task
    assert entry.is_valid_transition() is False
