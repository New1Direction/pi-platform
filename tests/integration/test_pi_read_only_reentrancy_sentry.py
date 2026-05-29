"""Integration tests for the PiReadOnlyReentrancySentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_read_only_reentrancy_sentry import (
    PiReadOnlyReentrancySentry,
    ReadOnlyReentrancyInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_READONLY_REENTRANCY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Read-Only Reentrancy Call
# =====================================================================
def test_read_only_reentrancy_vulnerable():
    """Verify that querying get_virtual_price without lock verification is flagged."""
    agent = PiReadOnlyReentrancySentry()

    solidity_code = """
    contract VulnerableReader {
        address public pool;

        function getPoolPrice() public view returns (uint) {
            // Queries external virtual price without nonReentrant or require/assert checks
            return CurvePool(pool).get_virtual_price();
        }
    }
    """
    inp = ReadOnlyReentrancyInput(file_path="VulnerableReader.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_readonly_reentrancy(inp)

    assert out.is_secure is False
    assert "getPoolPrice" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_READONLY_REENTRANCY"
    assert any("Read-Only Reentrancy exploits" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant Reader and Safety Warning Check
# =====================================================================
def test_read_only_reentrancy_compliant_with_warning():
    """Verify that a compliant reader with lock checks passes and emits safety warnings."""
    agent = PiReadOnlyReentrancySentry()

    solidity_code = """
    contract CompliantReader {
        address public pool;

        function getPoolPrice() public view returns (uint) {
            // Uses require lock validation
            require(CurvePool(pool).checkLock() == false, "locked");
            return CurvePool(pool).get_virtual_price();
        }

        function getTimestampedPrice() public view returns (uint) {
            // Relies on block.timestamp without validation check
            uint t = block.timestamp;
            return 100;
        }
    }
    """
    inp = ReadOnlyReentrancyInput(file_path="CompliantReader.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_readonly_reentrancy(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("relies on block.timestamp" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_read_only_reentrancy_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiReadOnlyReentrancySentry resolves majority votes."""
    monkeypatch.setenv("PI_READONLY_REENTRANCY_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract Reader {
        function getPrice() public view returns (uint) {
            return CurvePool(0x0).get_virtual_price();
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Read-only reentrancy risk on get_virtual_price"],
            "risk_score": 90.0,
            "status": "REJECTED_READONLY_REENTRANCY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Read-only reentrancy risk on get_virtual_price"],
            "risk_score": 90.0,
            "status": "REJECTED_READONLY_REENTRANCY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Read-only reentrancy risk on get_virtual_price"],
            "risk_score": 90.0,
            "status": "REJECTED_READONLY_REENTRANCY",
        },
    ]

    inp = OrchestratorInput(
        goal="read-only reentrancy on Reader.sol to check pool balance query safety",
        context={"file_path": "Reader.sol", "solidity_code": solidity_code, "mock_consensus_runs": mock_consensus_runs},
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiReadOnlyReentrancySentry" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_READONLY_REENTRANCY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
