"""Integration tests for the PiSelfDestructHunter micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_self_destruct_hunter import (
    PiSelfDestructHunter,
    SelfDestructHunterInput,
    SelfDestructHunterOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_SELFDESTRUCT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Selfdestruct Call (No Auth)
# =====================================================================
def test_self_destruct_hunter_vulnerable():
    """Verify that a function containing selfdestruct without access control is flagged."""
    agent = PiSelfDestructHunter()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Vulnerable {
        function killMe() public {
            selfdestruct(payable(msg.sender));
        }
    }
    """
    inp = SelfDestructHunterInput(
        file_path="Vulnerable.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_selfdestruct(inp)

    assert out.is_secure is False
    assert "killMe" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_SELFDESTRUCT_VULNERABILITY"
    assert any("without active access control" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant Selfdestruct Call (With Auth & Pausable)
# =====================================================================
def test_self_destruct_hunter_compliant():
    """Verify that an authorized selfdestruct call in a pausable contract passes."""
    agent = PiSelfDestructHunter()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Compliant {
        address public owner;
        bool public isPaused;

        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }

        function pause() public onlyOwner {
            isPaused = true;
        }

        function close() public onlyOwner {
            selfdestruct(payable(owner));
        }
    }
    """
    inp = SelfDestructHunterInput(
        file_path="Compliant.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_selfdestruct(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_self_destruct_hunter_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiSelfDestructHunter resolves majority votes."""
    monkeypatch.setenv("PI_SELFDESTRUCT_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Vuln {
        function destroy() public {
            selfdestruct(payable(msg.sender));
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["destroy"],
            "flagged_findings": ["Unprotected selfdestruct call found"],
            "risk_score": 95.0,
            "status": "REJECTED_SELFDESTRUCT_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["destroy"],
            "flagged_findings": ["Unprotected selfdestruct call found"],
            "risk_score": 95.0,
            "status": "REJECTED_SELFDESTRUCT_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["destroy"],
            "flagged_findings": ["Unprotected selfdestruct call found"],
            "risk_score": 95.0,
            "status": "REJECTED_SELFDESTRUCT_VULNERABILITY"
        }
    ]

    inp = OrchestratorInput(
        goal="selfdestruct hunter scan on Vuln.sol to detect insecure suicide calls",
        context={
            "file_path": "Vuln.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 95.0
    assert "PiSelfDestructHunter" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_SELFDESTRUCT_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
