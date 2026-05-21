"""Integration tests for PiDoSGasLimitsSentry — dual-use block gas limit and push/pull pattern auditor."""

import os
import pytest
from pydantic import ValidationError

from pi_micro_agents.pi_dos_gas_limits_sentry import (
    PiDoSGasLimitsSentry,
    DoSGasLimitsInput,
    DoSGasLimitsOutput,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_DOS_LOOP = """
pragma solidity 0.8.24;

contract VulnerableDoS {
    address[] public recipients;

    function refundAll() public {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1 ether);
        }
    }
}
"""

VULNERABLE_PUSH_PAYMENT = """
pragma solidity 0.8.24;

contract PushPaymentLoop {
    address[] public payees;
    IERC20 public token;

    function payout() public {
        for (uint256 i = 0; i < payees.length; i++) {
            token.transfer(payees[i], 100);
        }
    }
}
"""

SAFE_PULL_PAYMENT = """
pragma solidity 0.8.24;

contract SafePullPayment {
    mapping(address => uint256) public balances;

    function claimRefund() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_DOS_GAS_STRICT_MODE", raising=False)


# ── Tests: DoSGasLimitsSentry Heuristics ───────────────────────────────────

class TestDoSGasLimitsSentry:

    def test_vulnerable_dos_loop_detected(self) -> None:
        agent = PiDoSGasLimitsSentry()
        result = agent.audit_dos_gas(DoSGasLimitsInput(
            file_path="VulnerableDoS.sol",
            solidity_code=VULNERABLE_DOS_LOOP,
        ))
        assert isinstance(result, DoSGasLimitsOutput)
        assert result.is_secure is False
        assert "refundAll" in result.vulnerable_functions
        assert any("external call inside a loop" in finding for finding in result.flagged_findings)
        assert result.risk_score == 80.0
        assert result.status == "REJECTED_DOS_GAS_RISK"

    def test_vulnerable_push_payment_warning(self) -> None:
        agent = PiDoSGasLimitsSentry()
        result = agent.audit_dos_gas(DoSGasLimitsInput(
            file_path="PushPaymentLoop.sol",
            solidity_code=VULNERABLE_PUSH_PAYMENT,
        ))
        assert isinstance(result, DoSGasLimitsOutput)
        # It's an external call in loop, so it will flag as insecure and fail security check
        assert result.is_secure is False
        assert "payout" in result.vulnerable_functions
        assert any("Push-Payment Pattern detected in loop" in finding for finding in result.flagged_findings)

    def test_safe_pull_payment_passes(self) -> None:
        agent = PiDoSGasLimitsSentry()
        result = agent.audit_dos_gas(DoSGasLimitsInput(
            file_path="SafePullPayment.sol",
            solidity_code=SAFE_PULL_PAYMENT,
        ))
        assert isinstance(result, DoSGasLimitsOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_DOS_GAS_STRICT_MODE", "false")
        agent = PiDoSGasLimitsSentry()
        result = agent.audit_dos_gas(DoSGasLimitsInput(
            file_path="VulnerableDoS.sol",
            solidity_code=VULNERABLE_DOS_LOOP,
        ))
        assert isinstance(result, DoSGasLimitsOutput)
        assert result.is_secure is True
        assert result.status == "WARN_DOS_GAS_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiDoSGasLimitsSentry()
        result = agent.audit_dos_gas(DoSGasLimitsInput(
            file_path="SafePullPayment.sol",
            solidity_code=SAFE_PULL_PAYMENT,
        ))
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────

def test_orchestrator_nlp_routing_to_dos_gas_limits_sentry() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(OrchestratorInput(
        goal="Perform a block gas limit dos audit on loop functions.",
        context={
            "file_path": "VulnerableDoS.sol",
            "solidity_code": VULNERABLE_DOS_LOOP,
            "check_level": "STRICT"
        }
    ))
    assert result.success is False
    assert "PiDoSGasLimitsSentry" in result.routed_agent
    assert result.risk_score == 80.0
    assert any("external call inside a loop" in anomaly for anomaly in result.anomalies_detected)
