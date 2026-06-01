"""Objective Tracker.

Immutable objective integrity enforcement.
Every node receives a root_goal_id. Workers cannot mutate scope, target, intent.
Mismatch detected -> OBJECTIVE_DRIFT_DETECTED -> HARD_HALT.

The runtime owns objectives. Workers are stateless.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from pi_agent_chain.models import GovernanceViolation, WorkerResponse


class ObjectiveTracker:
    """Tracks immutable objective state across the entire pipeline.

    Registered at pipeline start. Verified at every worker boundary.
    """

    def __init__(self, root_goal_id: str, objective_scope: Dict[str, Any]) -> None:
        self.root_goal_id = root_goal_id
        self.objective_scope = objective_scope
        self._scope_hash = self._hash_scope(objective_scope)

    def validate_worker_response(self, worker_response: WorkerResponse) -> Optional[GovernanceViolation]:
        """Check that a worker response preserves objective integrity.

        Returns None if valid. Returns GovernanceViolation on drift.
        """
        if worker_response.root_goal_id != self.root_goal_id:
            return GovernanceViolation(
                violation_id=str(uuid.uuid4())[:16],
                rule="OBJECTIVE_DRIFT_DETECTED",
                worker_id=worker_response.worker_id,
                root_goal_id=worker_response.root_goal_id,
                severity="CRITICAL",
                context={
                    "expected_goal_id": self.root_goal_id,
                    "actual_goal_id": worker_response.root_goal_id,
                    "reason": "Worker emitted a different root_goal_id than registered",
                },
                action_taken="HALT",
            )

        # Workers should not expand scope
        # Workers must not mutate immutable scope keys. `artifacts` is a List[dict]
        # (models.WorkerResponse.artifacts); scan each artifact for a scope key
        # whose value the worker tried to change.
        artifacts = worker_response.artifacts or []
        if isinstance(artifacts, dict):  # tolerate a single-dict shape defensively
            artifacts = [artifacts]
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            for key, value in self.objective_scope.items():
                if key in artifact and artifact[key] != value:
                    return GovernanceViolation(
                        violation_id=str(uuid.uuid4())[:16],
                        rule="SCOPE_MUTATION",
                        worker_id=worker_response.worker_id,
                        root_goal_id=worker_response.root_goal_id,
                        severity="CRITICAL",
                        context={
                            "key": key,
                            "expected": value,
                            "actual": artifact[key],
                        },
                        action_taken="HALT",
                    )

        return None

    @staticmethod
    def _hash_scope(scope: Dict[str, Any]) -> str:
        import hashlib
        import json

        payload = json.dumps(scope, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()
