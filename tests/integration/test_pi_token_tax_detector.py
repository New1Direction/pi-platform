"""Integration tests for the PiTokenTaxDetector micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_token_tax_detector import (
    PiTokenTaxDetector,
    TokenTaxInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_TOKENTAX_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable fee-on-transfer (Token Tax detected)
# =====================================================================
def test_token_tax_vulnerable():
    """Verify that a contract containing a fee-on-transfer tax is flagged."""
    agent = PiTokenTaxDetector()

    solidity_code = """
    contract TaxToken {
        mapping(address => uint) public balanceOf;
        uint public feePercent = 5;

        function transfer(address to, uint amount) public returns (bool) {
            uint fee = (amount * feePercent) / 100;
            uint finalAmount = amount - fee;
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += finalAmount;
            emit Transfer(msg.sender, to, finalAmount);
            return true;
        }
    }
    """
    inp = TokenTaxInput(file_path="TaxToken.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_token_tax(inp)

    assert out.is_secure is False
    assert "transfer" in out.vulnerable_functions
    assert out.risk_score == 85.0
    assert out.status == "REJECTED_TOKENTAX_VULNERABILITY"
    assert any("fee-on-transfer" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant ERC-20 Token and Compliance Warnings
# =====================================================================
def test_token_tax_compliant_with_warning():
    """Verify standard compliant token and emission of ERC-20 compliance warnings."""
    agent = PiTokenTaxDetector()

    solidity_code = """
    contract NormalToken {
        mapping(address => uint) public balanceOf;

        function transfer(address to, uint amount) public returns (uint) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
    }
    """
    inp = TokenTaxInput(file_path="NormalToken.sol", solidity_code=solidity_code, check_level="STRICT")

    out = agent.audit_token_tax(inp)

    # It's secure since there's no tax, but it has interface compliance warnings
    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("does not explicitly return a boolean" in f for f in out.flagged_findings)
    assert any("does not emit the required 'Transfer' event" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_token_tax_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiTokenTaxDetector resolves majority votes."""
    monkeypatch.setenv("PI_TOKENTAX_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract TaxToken {
        mapping(address => uint) public balanceOf;
        uint public feePercent = 5;
        function transfer(address to, uint amount) public returns (bool) {
            uint fee = (amount * feePercent) / 100;
            uint finalAmount = amount - fee;
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += finalAmount;
            return true;
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["transfer"],
            "flagged_findings": ["fee-on-transfer detected"],
            "risk_score": 85.0,
            "status": "REJECTED_TOKENTAX_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["transfer"],
            "flagged_findings": ["fee-on-transfer detected"],
            "risk_score": 85.0,
            "status": "REJECTED_TOKENTAX_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["transfer"],
            "flagged_findings": ["fee-on-transfer detected"],
            "risk_score": 85.0,
            "status": "REJECTED_TOKENTAX_VULNERABILITY",
        },
    ]

    inp = OrchestratorInput(
        goal="token tax scan on TaxToken.sol to check ERC-20 fee compliance",
        context={
            "file_path": "TaxToken.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs,
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 85.0
    assert "PiTokenTaxDetector" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_TOKENTAX_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
