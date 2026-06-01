"""Integration tests for the PiBlockTimestampSentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_block_timestamp_sentry import (
    BlockTimestampInput,
    PiBlockTimestampSentry,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_TIMESTAMP_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Timestamp Reliance (Randomness)
# =====================================================================
def test_block_timestamp_vulnerable():
    """Verify that using block.timestamp for pseudo-randomness is flagged."""
    agent = PiBlockTimestampSentry()

    solidity_code = """
    contract RandomGame {
        function pickWinner() public view returns (uint) {
            // Dangerous reliance on block.timestamp for pseudo-randomness
            return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
        }
    }
    """
    inp = BlockTimestampInput(file_path="RandomGame.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_timestamp(inp)

    assert out.is_secure is False
    assert "pickWinner" in out.vulnerable_functions
    assert out.risk_score == 85.0
    assert out.status == "REJECTED_TIMESTAMP_VULNERABILITY"
    assert any("pseudo-randomness" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant Timestamp Usage & Warning Check
# =====================================================================
def test_block_timestamp_compliant_with_warning():
    """Verify that standard time limit checks pass and emit warnings for missing margins."""
    agent = PiBlockTimestampSentry()

    solidity_code = """
    contract Timelock {
        uint public releaseTime;

        function withdraw() public view {
            // Compares block.timestamp without standard explicit time constants
            require(block.timestamp > releaseTime, "locked");
        }
    }
    """
    inp = BlockTimestampInput(file_path="Timelock.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_timestamp(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("without using standard explicit time constants" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_block_timestamp_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiBlockTimestampSentry resolves majority votes."""
    monkeypatch.setenv("PI_TIMESTAMP_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract RandomGame {
        function pickWinner() public view returns (uint) {
            return uint(keccak256(abi.encodePacked(block.timestamp))) % 100;
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["pickWinner"],
            "flagged_findings": ["pseudo-randomness from block.timestamp"],
            "risk_score": 85.0,
            "status": "REJECTED_TIMESTAMP_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["pickWinner"],
            "flagged_findings": ["pseudo-randomness from block.timestamp"],
            "risk_score": 85.0,
            "status": "REJECTED_TIMESTAMP_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["pickWinner"],
            "flagged_findings": ["pseudo-randomness from block.timestamp"],
            "risk_score": 85.0,
            "status": "REJECTED_TIMESTAMP_VULNERABILITY",
        },
    ]

    inp = OrchestratorInput(
        goal="timestamp reliance scan on RandomGame.sol to verify block.timestamp audit and timelocks",
        context={
            "file_path": "RandomGame.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs,
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 85.0
    assert "PiBlockTimestampSentry" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_TIMESTAMP_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
