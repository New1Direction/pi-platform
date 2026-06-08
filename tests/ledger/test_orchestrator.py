from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.pi_runtime.ledger.models import AgentState, LedgerEntry
from src.pi_runtime.ledger.orchestrator import SquadOrchestrator
from src.pi_runtime.ledger.store import LedgerStore


def create_test_entry(from_state: AgentState, to_state: AgentState, entropy: int = -1):
    return LedgerEntry(
        task_id=uuid4(),
        actor_id="test-orchestrator",
        from_state=from_state,
        to_state=to_state,
        evidence_hash="0" * 64,
        timestamp=datetime.now(timezone.utc),
        provenance=[],
        entropy_delta=entropy,
    )


def test_orchestrator_starts_with_observation_task():
    store = LedgerStore(":memory:")
    orch = SquadOrchestrator(store)

    task = orch.get_next_task(target="orbstack")

    assert task is not None
    assert task.actor_id == "network-grpc-specialist"
    assert task.current_state == AgentState.UNASSIGNED
    assert "Observe and capture raw artifacts" in task.objective
    assert "00_Inbox" in task.input_artifact_path


def test_orchestrator_advances_linearly_through_states():
    store = LedgerStore(":memory:")
    orch = SquadOrchestrator(store)

    # Simulate progression
    states = [
        (AgentState.UNASSIGNED, AgentState.OBSERVED),
        (AgentState.OBSERVED, AgentState.INFERRED),
        (AgentState.INFERRED, AgentState.VERIFIED),
        (AgentState.VERIFIED, AgentState.COMMITTED),
    ]

    for from_state, to_state in states:
        entry = create_test_entry(from_state, to_state)
        orch.record_result(entry)

        next_task = orch.get_next_task("orbstack")
        assert next_task is not None
        assert next_task.current_state == to_state


def test_orchestrator_stops_at_terminal_state():
    store = LedgerStore(":memory:")
    orch = SquadOrchestrator(store)

    # Reach terminal state
    entry = create_test_entry(AgentState.COMMITTED, AgentState.ARCHIVED)
    orch.record_result(entry)

    next_task = orch.get_next_task("orbstack")
    assert next_task is None, "Should return None when pipeline is complete"


def test_orchestrator_rejects_invalid_ledger_state():
    store = LedgerStore(":memory:")
    orch = SquadOrchestrator(store)

    bad_entry = create_test_entry(AgentState.COMMITTED, AgentState.OBSERVED)  # illegal jump
    orch.record_result(bad_entry)  # This should succeed in store but...

    with pytest.raises(RuntimeError, match="invalid state"):
        orch.get_next_task("orbstack")


def test_orchestrator_returns_summary():
    store = LedgerStore(":memory:")
    orch = SquadOrchestrator(store)

    summary = orch.get_ledger_summary()
    assert summary["status"] == "UNASSIGNED"
    assert summary["progress"] == 0

    entry = create_test_entry(AgentState.UNASSIGNED, AgentState.OBSERVED)
    orch.record_result(entry)

    summary = orch.get_ledger_summary()
    assert summary["status"] == "OBSERVED"
    assert summary["progress"] == 1
    assert summary["last_actor"] == "test-orchestrator"
