"""Parity harness for the pi_agent_chain fail-closed gates (SchemaGate,
TransitionGate) vs the Rust port (pi_core.gate_op).

Each gate returns either None (valid) or a GovernanceViolation. The violation's
`violation_id` (uuid) and `detected_at` (utcnow) are non-deterministic and
excluded; the rule/severity/context/action_taken are compared byte-for-byte
(incl. the insertion-ordered context.payload_keys, which exercises preserve_order).

Run:  PYTHONPATH=.:../../src python governance_gates_parity.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pi_core  # noqa: E402
from pi_agent_chain.governance.schema_gate import SchemaGate  # noqa: E402
from pi_agent_chain.governance.transition_gate import TransitionGate  # noqa: E402
from pi_agent_chain.models import WorkerResponse  # noqa: E402

mismatches = []
DETERMINISTIC = ("rule", "worker_id", "root_goal_id", "severity", "context", "action_taken")


def cmp(label, a, b):
    if a != b:
        mismatches.append((label, a, b))


def strip(viol):
    """Python GovernanceViolation -> deterministic dict (drop uuid + utcnow)."""
    if viol is None:
        return None
    d = viol.model_dump()
    return {k: d[k] for k in DETERMINISTIC}


SG = SchemaGate()
TG = TransitionGate()


def run_schema_gate():
    cases = [
        ("verifier", {"payload": {}, "type": "X"}),
        ("verifier", {"type": "X"}),                          # missing payload
        ("verifier", {"payload": {}}),                        # missing type
        ("verifier", {"payload": "nope", "type": "X"}),       # payload not object
        ("verifier", {"payload": {}, "type": 123}),           # type not string
        ("verifier", {"payload": [], "type": "X"}),           # payload is list
        ("verifier", {"payload": {}, "type": True}),          # type is bool
        ("unknown_worker", {"anything": 1}),                  # unregistered -> valid
        ("acquisition_gateway", {"payload": {"a": 1}, "type": "T"}),
        ("verifier", {"z": 1, "a": 2, "type": "X"}),          # missing payload; payload_keys order!
        ("spec_synthesizer", {"type": "X", "payload": {}, "extra": 9}),  # extra ignored
    ]
    for worker_id, payload in cases:
        wr = WorkerResponse(root_goal_id="g1", worker_id=worker_id, status="SUCCESS")
        py = strip(SG.validate(worker_id, payload, wr))
        rs = json.loads(pi_core.gate_op("schema_gate", json.dumps(
            {"worker_id": worker_id, "payload": payload, "root_goal_id": "g1"})))
        cmp(f"schema_gate[{worker_id}/{list(payload.keys())}]", py, rs)


def run_transition_gate():
    cases = [
        ("REGISTERED", "SCOPED", "SUCCESS", 0, 0),
        ("REGISTERED", "COMPLETED", "SUCCESS", 0, 0),          # no rule
        ("REGISTERED", "SCOPED", "FAILURE", 0, 0),             # status mismatch
        ("EXTRACTING", "FAILED", "FAILURE", 0, 0),             # failure transition ok
        ("EXTRACTING", "FAILED", "SUCCESS", 0, 0),             # status mismatch
        ("REGISTERED", "SCOPED", "SUCCESS", 3, 0),             # max depth
        ("REGISTERED", "SCOPED", "SUCCESS", 0, 8),             # branch overflow
        ("FAILED", "RETRY_PENDING", "RETRYABLE_FAILURE", 0, 0),
        ("EXTRACTING", "INVALID_EVIDENCE", "INSUFFICIENT_EVIDENCE", 0, 0),
        ("VERIFYING", "INVALID_EVIDENCE", "VERIFICATION_MISMATCH", 0, 0),
        ("REGISTERED", "SCOPED", "FAILURE", 3, 0),             # status checked before depth
        ("COMPLETED", "REGISTERED", "SUCCESS", 0, 0),          # no rule
    ]
    for cur, prop, status, depth, branch in cases:
        wr = WorkerResponse(root_goal_id="g1", worker_id="w1", status=status)
        py = strip(TG.validate(cur, prop, wr, depth=depth, branch_count=branch))
        rs = json.loads(pi_core.gate_op("transition_gate", json.dumps(
            {"current_state": cur, "proposed_state": prop, "status": status,
             "worker_id": "w1", "root_goal_id": "g1", "depth": depth, "branch_count": branch})))
        cmp(f"transition_gate[{cur}->{prop}/{status}/d{depth}/b{branch}]", py, rs)


def main():
    run_schema_gate()
    run_transition_gate()
    if mismatches:
        print(f"GOVERNANCE-GATES PARITY: {len(mismatches)} MISMATCH(es)\n")
        for label, a, b in mismatches[:12]:
            print(f"  [{label}]\n    python: {a}\n    rust:   {b}\n")
        sys.exit(1)
    print("GOVERNANCE-GATES PARITY: ALL MATCH — SchemaGate + TransitionGate violations "
          "(rule/severity/context/action, incl. ordered payload_keys) byte-identical")


if __name__ == "__main__":
    main()
