"""Integration tests for the PiTxOriginSentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_tx_origin_sentry import (
    PiTxOriginSentry,
    TxOriginInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_TXORIGIN_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable tx.origin Authentication
# =====================================================================
def test_tx_origin_vulnerable():
    """Verify that using tx.origin for authorization is flagged."""
    agent = PiTxOriginSentry()

    solidity_code = """
    contract Phishable {
        address public owner;

        function withdraw(address payable to) public {
            require(tx.origin == owner, "not owner");
            to.transfer(address(this).balance);
        }
    }
    """
    inp = TxOriginInput(file_path="Phishable.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_tx_origin(inp)

    assert out.is_secure is False
    assert "withdraw" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_TXORIGIN_VULNERABILITY"
    assert any("uses 'tx.origin' for authorization" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant EIP-2771 / msg.sender Verification
# =====================================================================
def test_tx_origin_compliant_with_warning():
    """Verify compliant contract and emission of EIP-2771 compliance warnings."""
    agent = PiTxOriginSentry()

    solidity_code = """
    contract ERC2771Compliant {
        address public owner;

        function isTrustedForwarder(address forwarder) public view returns (bool) {
            return true;
        }

        function withdraw(address payable to) public {
            require(msg.sender == owner, "not owner");
            to.transfer(address(this).balance);
        }
    }
    """
    inp = TxOriginInput(file_path="ERC2771Compliant.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_tx_origin(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("accesses msg.sender directly" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_tx_origin_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiTxOriginSentry resolves majority votes."""
    monkeypatch.setenv("PI_TXORIGIN_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract Phishable {
        function withdraw() public {
            require(tx.origin == msg.sender);
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["withdraw"],
            "flagged_findings": ["Uses tx.origin"],
            "risk_score": 90.0,
            "status": "REJECTED_TXORIGIN_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["withdraw"],
            "flagged_findings": ["Uses tx.origin"],
            "risk_score": 90.0,
            "status": "REJECTED_TXORIGIN_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["withdraw"],
            "flagged_findings": ["Uses tx.origin"],
            "risk_score": 90.0,
            "status": "REJECTED_TXORIGIN_VULNERABILITY",
        },
    ]

    inp = OrchestratorInput(
        goal="tx.origin check on Phishable.sol to verify meta-tx and phishing protection",
        context={
            "file_path": "Phishable.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs,
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiTxOriginSentry" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_TXORIGIN_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
