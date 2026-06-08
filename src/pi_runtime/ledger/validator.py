from datetime import datetime
from typing import List, Tuple

from .models import AgentState, LedgerEntry


class ValidationResult:
    """Immutable result of state machine validation."""

    def __init__(self, is_valid: bool, reason: str, entropy_ok: bool = True):
        self.is_valid = is_valid
        self.reason = reason
        self.entropy_ok = entropy_ok
        self.timestamp = datetime.now()


class StateMachineValidator:
    """Fail-closed state machine validator for the PI Agents Analysis Squad.

    Enforces:
    - Strict linear progression (no jumping states)
    - Entropy must never increase (must be <= 0)
    - All transitions must be explicitly allowed
    - Zero tolerance for invalid or ambiguous transitions
    """

    # Strict allowed transitions (must be linear and deterministic)
    VALID_TRANSITIONS = {
        AgentState.UNASSIGNED: {AgentState.OBSERVED},
        AgentState.OBSERVED: {AgentState.INFERRED},
        AgentState.INFERRED: {AgentState.VERIFIED},
        AgentState.VERIFIED: {AgentState.COMMITTED},
        AgentState.COMMITTED: {AgentState.ARCHIVED},
    }

    def validate_transition(self, entry: LedgerEntry) -> ValidationResult:
        """Fail-closed validation of a single ledger entry.

        Returns ValidationResult with clear reason on any failure.
        """
        if entry.entropy_delta > 0:
            return ValidationResult(
                is_valid=False,
                reason=f"Entropy increased ({entry.entropy_delta}). Violates anti-entropy rule.",
                entropy_ok=False,
            )

        allowed = self.VALID_TRANSITIONS.get(entry.from_state, set())
        if entry.to_state not in allowed:
            return ValidationResult(
                is_valid=False,
                reason=f"Invalid state transition: {entry.from_state} → {entry.to_state}. "
                f"Allowed from {entry.from_state}: {allowed}",
            )

        return ValidationResult(
            is_valid=True,
            reason="Transition valid and entropy non-increasing",
            entropy_ok=True,
        )

    def validate_chain(self, entries: List[LedgerEntry]) -> Tuple[bool, List[str]]:
        """Validate an entire ledger chain for consistency.

        Returns (is_valid, list_of_violations).
        Completely fail-closed — any single violation fails the whole chain.
        """
        violations = []

        for i, entry in enumerate(entries):
            result = self.validate_transition(entry)
            if not result.is_valid:
                violations.append(f"Entry {i} (task={entry.task_id}): {result.reason}")

        if violations:
            return False, violations

        # Additional chain-level checks can be added here (e.g. sequential task_ids, hash chaining)
        return True, ["Chain is valid and deterministic"]


# Global singleton validator (used by orchestrator and store)
validator = StateMachineValidator()
