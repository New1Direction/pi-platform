"""Integration tests for the PiUninitializedStateSentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_uninitialized_state_sentry import (
    PiUninitializedStateSentry,
    UninitializedInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_UNINITIALIZED_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Uninitialized State Variable
# =====================================================================
def test_uninitialized_state_variable():
    """Verify that a state variable never initialized in constructor is flagged."""
    agent = PiUninitializedStateSentry()

    solidity_code = """
    contract UninitializedVar {
        address public admin;

        constructor() {
            // admin is never set
        }
    }
    """
    inp = UninitializedInput(file_path="UninitializedVar.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_uninitialized(inp)

    assert out.is_secure is False
    assert "admin" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_UNINITIALIZED_STATE"
    assert any("is never initialized" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Vulnerable Upgradeable Initializer (Missing modifier & parent init)
# =====================================================================
def test_uninitialized_upgradeable_vulnerable():
    """Verify that upgradeable initializer lacking modifier or parent init is flagged."""
    agent = PiUninitializedStateSentry()

    solidity_code = """
    contract UpgradeableToken is ERC20Upgradeable {
        function initialize() public {
            // Missing modifier
        }
    }
    """
    inp = UninitializedInput(file_path="UpgradeableToken.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_uninitialized(inp)

    assert out.is_secure is False
    assert "initialize" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_UNINITIALIZED_STATE"
    assert any("missing the OpenZeppelin 'initializer' modifier" in f for f in out.flagged_findings)
    assert any("does not invoke the parent initializer" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Compliant Initializer and State Variables
# =====================================================================
def test_uninitialized_state_compliant():
    """Verify that correctly initialized variables and modifiers pass the audit."""
    agent = PiUninitializedStateSentry()

    solidity_code = """
    contract CompliantVar {
        address public admin = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        uint public count;

        constructor() {
            count = 1;
        }
    }
    """
    inp = UninitializedInput(file_path="CompliantVar.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_uninitialized(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 4: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_uninitialized_state_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiUninitializedStateSentry resolves majority votes."""
    monkeypatch.setenv("PI_UNINITIALIZED_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract UninitializedVar {
        address public admin;
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["admin"],
            "flagged_findings": ["State variable admin is never initialized"],
            "risk_score": 90.0,
            "status": "REJECTED_UNINITIALIZED_STATE",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["admin"],
            "flagged_findings": ["State variable admin is never initialized"],
            "risk_score": 90.0,
            "status": "REJECTED_UNINITIALIZED_STATE",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["admin"],
            "flagged_findings": ["State variable admin is never initialized"],
            "risk_score": 90.0,
            "status": "REJECTED_UNINITIALIZED_STATE",
        },
    ]

    inp = OrchestratorInput(
        goal="uninitialized storage scan on UninitializedVar.sol to check modifier and constructor safety",
        context={
            "file_path": "UninitializedVar.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs,
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiUninitializedStateSentry" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_UNINITIALIZED_STATE" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
