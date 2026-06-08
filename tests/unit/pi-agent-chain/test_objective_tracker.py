"""The SCOPE_MUTATION gate must actually fire.

Finding: the gate iterated `worker_response.artifacts` (a List[dict]) as if it
were a dict and guarded on `isinstance(..., dict)` (always False), so a worker
could rewrite an immutable scope key (e.g. change the target domain) with no
violation raised.
"""

from __future__ import annotations

from pi_agent_chain.governance.objective_tracker import ObjectiveTracker
from pi_agent_chain.models import WorkerResponse


def _resp(artifacts, goal_id="g1"):
    return WorkerResponse(root_goal_id=goal_id, worker_id="w1", artifacts=artifacts)


def test_scope_mutation_is_detected():
    tracker = ObjectiveTracker("g1", {"target": "safe.example.com", "mode": "passive"})
    resp = _resp([{"target": "attacker.evil", "mode": "active_exploit"}])
    v = tracker.validate_worker_response(resp)
    assert v is not None
    assert v.rule == "SCOPE_MUTATION"
    assert v.context["key"] in {"target", "mode"}


def test_scope_preserved_passes():
    tracker = ObjectiveTracker("g1", {"target": "safe.example.com"})
    resp = _resp([{"target": "safe.example.com", "extra": 1}])
    assert tracker.validate_worker_response(resp) is None


def test_artifact_without_scope_keys_passes():
    tracker = ObjectiveTracker("g1", {"target": "safe.example.com"})
    resp = _resp([{"result": "ok"}])
    assert tracker.validate_worker_response(resp) is None


def test_goal_id_mismatch_still_detected():
    tracker = ObjectiveTracker("g1", {"target": "x"})
    v = tracker.validate_worker_response(_resp([], goal_id="g2"))
    assert v is not None and v.rule == "OBJECTIVE_DRIFT_DETECTED"
