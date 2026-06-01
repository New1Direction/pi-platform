"""Integration tests for the PiShadowedVariableDetector micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_shadowed_variable_detector import (
    PiShadowedVariableDetector,
    ShadowedVariableInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_SHADOW_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Shadowed Variable Detected
# =====================================================================
def test_shadowed_variable_detected():
    """Verify that a function parameter shadowing a state variable is flagged."""
    agent = PiShadowedVariableDetector()

    solidity_code = """
    contract Shadowed {
        address public owner;

        function setOwner(address owner) public {
            // parameter owner shadows state variable owner
        }
    }
    """
    inp = ShadowedVariableInput(file_path="Shadowed.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_shadowed(inp)

    assert out.is_secure is False
    assert "setOwner" in out.vulnerable_functions
    assert out.risk_score == 80.0
    assert out.status == "REJECTED_SHADOW_VULNERABILITY"
    assert any("shadows a state-level variable" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Unused Variable Optimization Warning
# =====================================================================
def test_shadowed_variable_unused_warning():
    """Verify that unused function parameters emit optimization warnings."""
    agent = PiShadowedVariableDetector()

    solidity_code = """
    contract Unused {
        function add(uint a, uint b) public pure returns (uint) {
            // b is unused
            return a;
        }
    }
    """
    inp = ShadowedVariableInput(file_path="Unused.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_shadowed(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("declares parameter 'b' which is never used" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_shadowed_variable_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiShadowedVariableDetector resolves majority votes."""
    monkeypatch.setenv("PI_SHADOW_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract Shadowed {
        address public owner;
        function setOwner(address owner) public {}
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["setOwner"],
            "flagged_findings": ["Parameter owner shadows state variable owner"],
            "risk_score": 80.0,
            "status": "REJECTED_SHADOW_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["setOwner"],
            "flagged_findings": ["Parameter owner shadows state variable owner"],
            "risk_score": 80.0,
            "status": "REJECTED_SHADOW_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["setOwner"],
            "flagged_findings": ["Parameter owner shadows state variable owner"],
            "risk_score": 80.0,
            "status": "REJECTED_SHADOW_VULNERABILITY",
        },
    ]

    inp = OrchestratorInput(
        goal="shadowed variable scan on Shadowed.sol to check unused variable optimization gas",
        context={
            "file_path": "Shadowed.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs,
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 80.0
    assert "PiShadowedVariableDetector" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_SHADOW_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
