from datetime import datetime, timezone
from uuid import uuid4

from src.pi_runtime.ledger.gates import AntiHallucinationGate, gate
from src.pi_runtime.ledger.models import AgentState, LedgerEntry
from src.pi_runtime.ledger.store import LedgerStore


def create_entry(
    actor="network-grpc-specialist",
    from_state=AgentState.UNASSIGNED,
    to_state=AgentState.OBSERVED,
    entropy=-2,
    hash_val=None,
):
    if hash_val is None:
        hash_val = "a" * 64
    # Use model_construct to bypass frozen model restrictions during testing
    return LedgerEntry.model_construct(
        task_id=uuid4(),
        actor_id=actor,
        from_state=from_state,
        to_state=to_state,
        evidence_hash=hash_val,
        timestamp=datetime.now(timezone.utc),
        provenance=[],
        entropy_delta=entropy,
    )


def test_gate_allows_valid_specialist():
    entry = create_entry(actor="network-grpc-specialist")
    ledger = []
    passed, failures = gate.run_all_gates(entry, ledger)
    assert passed is True
    assert len(failures) == 0


def test_gate_rejects_unknown_actor():
    entry = create_entry(actor="random-hallucinated-agent")
    passed, failures = gate.run_all_gates(entry, [])
    assert passed is False
    assert any("Unauthorized actor" in f for f in failures)


def test_gate_rejects_zero_hash():
    entry = create_entry(hash_val="0" * 64)
    passed, failures = gate.run_all_gates(entry, [])
    assert passed is False
    assert any("cannot be zero" in f for f in failures)


def test_gate_rejects_invalid_hash_format():
    entry = create_entry(hash_val="not-a-valid-hash")
    passed, failures = gate.run_all_gates(entry, [])
    assert passed is False
    assert any("not a valid 64-character" in f for f in failures)


def test_gate_rejects_invalid_transition_via_validator():
    entry = create_entry(from_state=AgentState.COMMITTED, to_state=AgentState.OBSERVED)
    passed, failures = gate.run_all_gates(entry, [])
    assert passed is False
    assert any("Invalid state transition" in f for f in failures)


def test_gate_accepts_valid_provenance():
    store = LedgerStore(":memory:")
    previous = create_entry(to_state=AgentState.OBSERVED)
    store.append(previous)

    current = create_entry(from_state=AgentState.OBSERVED, to_state=AgentState.INFERRED)
    # LedgerEntry is frozen in pydantic v2; matched here by the same
    # object.__setattr__ trick model_post_init uses internally.
    object.__setattr__(current, "provenance", [previous.task_id])

    passed, failures = gate.run_all_gates(current, store.get_all())
    assert passed is True


def test_gate_global_instance_exists():
    assert gate is not None
    assert isinstance(gate, AntiHallucinationGate)
