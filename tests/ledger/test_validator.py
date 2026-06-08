from datetime import datetime, timezone
from uuid import uuid4

from src.pi_runtime.ledger.models import AgentState, LedgerEntry
from src.pi_runtime.ledger.validator import StateMachineValidator, validator


def create_entry(from_state: AgentState, to_state: AgentState, entropy_delta: int = -1):
    """Create test entry using model_construct to bypass frozen validation during test setup."""
    return LedgerEntry.model_construct(
        task_id=uuid4(),
        actor_id="test-validator",
        from_state=from_state,
        to_state=to_state,
        evidence_hash="0" * 64,
        timestamp=datetime.now(timezone.utc),
        provenance=[],
        entropy_delta=entropy_delta,
    )


def test_validator_allows_valid_linear_transitions():
    v = StateMachineValidator()

    valid_cases = [
        (AgentState.UNASSIGNED, AgentState.OBSERVED),
        (AgentState.OBSERVED, AgentState.INFERRED),
        (AgentState.INFERRED, AgentState.VERIFIED),
        (AgentState.VERIFIED, AgentState.COMMITTED),
        (AgentState.COMMITTED, AgentState.ARCHIVED),
    ]

    for from_state, to_state in valid_cases:
        entry = create_entry(from_state, to_state, entropy_delta=-5)
        result = v.validate_transition(entry)
        assert result.is_valid is True, f"Failed on {from_state} → {to_state}"
        assert result.entropy_ok is True


def test_validator_rejects_invalid_transitions():
    v = StateMachineValidator()

    invalid_cases = [
        (AgentState.UNASSIGNED, AgentState.INFERRED),  # jump
        (AgentState.OBSERVED, AgentState.COMMITTED),  # jump
        (AgentState.VERIFIED, AgentState.OBSERVED),  # backward
        (AgentState.ARCHIVED, AgentState.UNASSIGNED),  # impossible
    ]

    for from_state, to_state in invalid_cases:
        entry = create_entry(from_state, to_state)
        result = v.validate_transition(entry)
        assert result.is_valid is False
        assert "Invalid state transition" in result.reason


def test_validator_rejects_entropy_increase():
    v = StateMachineValidator()
    entry = create_entry(AgentState.OBSERVED, AgentState.INFERRED, entropy_delta=+3)

    result = v.validate_transition(entry)
    assert result.is_valid is False
    assert "Entropy increased" in result.reason
    assert result.entropy_ok is False


def test_validator_chain_validation():
    v = StateMachineValidator()

    good_chain = [
        create_entry(AgentState.UNASSIGNED, AgentState.OBSERVED, -2),
        create_entry(AgentState.OBSERVED, AgentState.INFERRED, -1),
        create_entry(AgentState.INFERRED, AgentState.VERIFIED, -3),
    ]

    is_valid, messages = v.validate_chain(good_chain)
    assert is_valid is True
    assert any("valid" in msg.lower() for msg in messages)

    bad_chain = good_chain + [create_entry(AgentState.VERIFIED, AgentState.OBSERVED)]
    is_valid, messages = v.validate_chain(bad_chain)
    assert is_valid is False
    assert len(messages) > 0
    assert any("Invalid state transition" in msg for msg in messages)


def test_global_validator_instance_exists():
    assert validator is not None
    assert isinstance(validator, StateMachineValidator)
