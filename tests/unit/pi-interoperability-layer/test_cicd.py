"""Tests for CI/CD governance integration."""

from __future__ import annotations

from pi_interoperability_layer.cicd import (
    PRGateConfig,
    PRGateResult,
    ReplayValidationGate,
    PolicyEnforcementHook,
    GitHubActionsWorkflow,
)


def test_pr_gate_all_pass() -> None:
    gate = PRGateConfig(
        gate_id="g1",
        required_passes=["boundary", "layer"],
        required_artifacts=["SemanticIRTrace"],
        require_replay_verification=True,
        require_policy_drift_check=True,
        fail_closed=True,
    )
    results = {
        "boundary": True,
        "layer": True,
        "artifact_SemanticIRTrace": "fp1",
        "replay_verified": True,
        "policy_drift_check": True,
    }
    outcome = gate.evaluate(results)
    assert outcome.status == "PASS"
    assert outcome.violations == []


def test_pr_gate_missing_pass() -> None:
    gate = PRGateConfig(gate_id="g1", required_passes=["boundary"], fail_closed=True)
    results = {"boundary": False}
    outcome = gate.evaluate(results)
    assert outcome.status == "BLOCKED"
    assert any("boundary failed" in v for v in outcome.violations)


def test_pr_gate_fail_closed_disabled() -> None:
    gate = PRGateConfig(
        gate_id="g1", required_passes=["boundary"], fail_closed=False
    )
    results = {"boundary": False}
    outcome = gate.evaluate(results)
    assert outcome.status == "FAIL"


def test_replay_gate_pass() -> None:
    gate = ReplayValidationGate(
        gate_id="rg1",
        required_ledger_id="L1",
        min_verified_sequence=5,
        allowed_replay_classes=["IDEMPOTENT"],
        sandbox_required=True,
        production_replay_prohibited=True,
    )
    summary = {
        "ledger_id": "L1",
        "last_verified_sequence": 10,
        "replay_class": "IDEMPOTENT",
        "sandboxed": True,
        "production_replay": False,
    }
    assert gate.evaluate(summary) == "PASS"


def test_replay_gate_wrong_ledger() -> None:
    gate = ReplayValidationGate(gate_id="rg1", required_ledger_id="L1")
    summary = {"ledger_id": "L2"}
    assert gate.evaluate(summary) == "BLOCKED"


def test_replay_gate_production_replay() -> None:
    gate = ReplayValidationGate(
        gate_id="rg1",
        required_ledger_id="L1",
        production_replay_prohibited=True,
    )
    summary = {
        "ledger_id": "L1",
        "last_verified_sequence": 0,
        "replay_class": "IDEMPOTENT",
        "sandboxed": True,
        "production_replay": True,
    }
    assert gate.evaluate(summary) == "BLOCKED"


def test_policy_enforcement_hook_missing() -> None:
    hook = PolicyEnforcementHook(
        hook_id="h1",
        hook_type="PRE_MERGE",
        required_validations=["boundary"],
        required_contracts=["SemanticIRTrace"],
    )
    missing = hook.check_required({})
    assert "validation:boundary" in missing
    assert "contract:SemanticIRTrace" in missing


def test_policy_enforcement_hook_present() -> None:
    hook = PolicyEnforcementHook(
        hook_id="h1",
        hook_type="PRE_MERGE",
        required_validations=["boundary"],
        required_contracts=["SemanticIRTrace"],
    )
    missing = hook.check_required(
        {"validation_boundary": True, "contract_SemanticIRTrace": True}
    )
    assert missing == []


def test_github_actions_workflow_generate_yaml() -> None:
    wf = GitHubActionsWorkflow(
        workflow_id="wf1",
        name="Governance Gate",
        on_events=["pull_request"],
        jobs={
            "validate": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    "uses: actions/checkout@v4",
                    "run: pi-contracts validate",
                ],
            }
        },
    )
    yaml = wf.generate_yaml()
    assert "name: Governance Gate" in yaml
    assert "on:" in yaml
    assert "jobs:" in yaml
    assert "validate:" in yaml
