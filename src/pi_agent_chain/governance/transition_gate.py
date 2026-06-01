"""Transition Gate.

Deterministic finite-state machine enforcement.
Every state transition is validated against an explicit rule set.
Invalid transitions -> GovernanceViolation -> HARD_HALT.

No worker controls flow. The runtime approves transitions.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from pi_agent_chain.models import (
    GovernanceViolation,
    RuntimeState,
    TransitionRule,
    WorkerResponse,
    WorkerStatus,
)

# Canonical allowed transitions
CANONICAL_TRANSITIONS: List[TransitionRule] = [
    # Linear pipeline
    TransitionRule(from_state=RuntimeState.REGISTERED, to_state=RuntimeState.SCOPED),
    TransitionRule(from_state=RuntimeState.SCOPED, to_state=RuntimeState.CAPTURE_READY),
    TransitionRule(from_state=RuntimeState.CAPTURE_READY, to_state=RuntimeState.CAPTURING),
    TransitionRule(from_state=RuntimeState.CAPTURING, to_state=RuntimeState.NORMALIZING),
    TransitionRule(from_state=RuntimeState.NORMALIZING, to_state=RuntimeState.EXTRACTING),
    TransitionRule(from_state=RuntimeState.EXTRACTING, to_state=RuntimeState.ASSEMBLING_IR),
    TransitionRule(from_state=RuntimeState.ASSEMBLING_IR, to_state=RuntimeState.GENERATING_SPEC),
    TransitionRule(from_state=RuntimeState.GENERATING_SPEC, to_state=RuntimeState.COMPLETED),
    # Failure transitions (any state -> failure states)
    TransitionRule(
        from_state=RuntimeState.REGISTERED, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.SCOPED, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.CAPTURE_READY, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.CAPTURING, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.NORMALIZING, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.EXTRACTING, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.VERIFYING, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.ASSEMBLING_IR, to_state=RuntimeState.FAILED, required_worker_status=WorkerStatus.FAILURE
    ),
    TransitionRule(
        from_state=RuntimeState.GENERATING_SPEC,
        to_state=RuntimeState.FAILED,
        required_worker_status=WorkerStatus.FAILURE,
    ),
    # Retry transitions
    TransitionRule(
        from_state=RuntimeState.FAILED,
        to_state=RuntimeState.RETRY_PENDING,
        required_worker_status=WorkerStatus.RETRYABLE_FAILURE,
    ),
    # Invalid evidence
    TransitionRule(
        from_state=RuntimeState.EXTRACTING,
        to_state=RuntimeState.INVALID_EVIDENCE,
        required_worker_status=WorkerStatus.INSUFFICIENT_EVIDENCE,
    ),
    TransitionRule(
        from_state=RuntimeState.VERIFYING,
        to_state=RuntimeState.INVALID_EVIDENCE,
        required_worker_status=WorkerStatus.VERIFICATION_MISMATCH,
    ),
]


class TransitionGate:
    """Deterministic state transition validator.

    Workers propose next_state. The gate approves or rejects.
    """

    def __init__(self, rules: Optional[List[TransitionRule]] = None) -> None:
        self.rules = rules or CANONICAL_TRANSITIONS
        self._index = {(r.from_state, r.to_state): r for r in self.rules}

    def validate(
        self,
        current_state: str,
        proposed_state: str,
        worker_response: WorkerResponse,
        depth: int = 0,
        branch_count: int = 0,
    ) -> Optional[GovernanceViolation]:
        """Validate a proposed state transition.

        Returns None if valid. Returns GovernanceViolation if invalid.
        """
        key = (current_state, proposed_state)
        rule = self._index.get(key)

        if rule is None:
            return GovernanceViolation(
                violation_id=str(uuid.uuid4())[:16],
                rule="TRANSITION_NOT_ALLOWED",
                worker_id=worker_response.worker_id,
                root_goal_id=worker_response.root_goal_id,
                severity="CRITICAL",
                context={
                    "from_state": current_state,
                    "proposed_state": proposed_state,
                    "reason": "No rule authorizes this transition",
                },
                action_taken="HALT",
            )

        # Check worker status
        if worker_response.status != rule.required_worker_status:
            # Allow failure transitions even if worker says FAILURE
            if rule.required_worker_status == WorkerStatus.FAILURE and worker_response.status == WorkerStatus.FAILURE:
                pass  # OK
            else:
                return GovernanceViolation(
                    violation_id=str(uuid.uuid4())[:16],
                    rule="STATUS_MISMATCH",
                    worker_id=worker_response.worker_id,
                    root_goal_id=worker_response.root_goal_id,
                    severity="ERROR",
                    context={
                        "required_status": rule.required_worker_status,
                        "actual_status": worker_response.status,
                    },
                    action_taken="HALT",
                )

        # Check depth cap
        if depth >= rule.max_depth:
            return GovernanceViolation(
                violation_id=str(uuid.uuid4())[:16],
                rule="MAX_DEPTH_EXCEEDED",
                worker_id=worker_response.worker_id,
                root_goal_id=worker_response.root_goal_id,
                severity="CRITICAL",
                context={"depth": depth, "max_depth": rule.max_depth},
                action_taken="HALT",
            )

        # Check branch overflow
        if branch_count >= rule.max_branch_count:
            return GovernanceViolation(
                violation_id=str(uuid.uuid4())[:16],
                rule="BRANCH_OVERFLOW",
                worker_id=worker_response.worker_id,
                root_goal_id=worker_response.root_goal_id,
                severity="CRITICAL",
                context={"branch_count": branch_count, "max_branch_count": rule.max_branch_count},
                action_taken="HALT",
            )

        return None

    def is_terminal(self, state: str) -> bool:
        """Check if state is terminal (no further transitions allowed)."""
        return state in {RuntimeState.COMPLETED, RuntimeState.FAILED, RuntimeState.INVALID_EVIDENCE}
