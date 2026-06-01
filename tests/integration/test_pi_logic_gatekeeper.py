"""Integration tests for PiLogicGatekeeper — dual-use logic flow and dead code auditor."""

import pytest

from pi_micro_agents.pi_logic_gatekeeper import (
    LogicGatekeeperInput,
    LogicGatekeeperOutput,
    PiLogicGatekeeper,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_MODIFIER = """
pragma solidity 0.8.24;

contract BadModifier {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        // missing merge wildcard '_;'
    }

    function restrictedAction() public onlyOwner {
        // this will never be executed but bypasses compiler error
    }
}
"""

VULNERABLE_TAUTOLOGY = """
pragma solidity 0.8.24;

contract TautologyCheck {
    function verify(uint256 value) public pure {
        require(value >= 0, "Invalid value"); // tautology
    }
}
"""

DEAD_CODE_UNREACHABLE = """
pragma solidity 0.8.24;

contract UnreachableCode {
    function process() public pure returns (uint256) {
        return 42;
        uint256 a = 100; // unreachable
    }
}
"""

SAFE_CONTRACT = """
pragma solidity 0.8.24;

contract SafeContract {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function verify(uint256 value) public pure returns (bool) {
        if (value > 0) {
            return true;
        }
        return false;
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_LOGIC_STRICT_MODE", raising=False)


# ── Tests: LogicGatekeeper Heuristics ────────────────────────────────────────


class TestLogicGatekeeper:
    def test_vulnerable_modifier_detected(self) -> None:
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="BadModifier.sol",
                solidity_code=VULNERABLE_MODIFIER,
            )
        )
        assert isinstance(result, LogicGatekeeperOutput)
        assert result.is_secure is False
        assert "onlyOwner" in result.vulnerable_functions
        assert any("merge wildcard" in finding for finding in result.flagged_findings)
        assert result.risk_score == 85.0
        assert result.status == "REJECTED_LOGIC_RISK"

    def test_vulnerable_tautology_detected(self) -> None:
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="TautologyCheck.sol",
                solidity_code=VULNERABLE_TAUTOLOGY,
            )
        )
        assert isinstance(result, LogicGatekeeperOutput)
        assert result.is_secure is False
        assert "verify" in result.vulnerable_functions
        assert any("tautological check" in finding for finding in result.flagged_findings)

    def test_dead_code_detected(self) -> None:
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="UnreachableCode.sol",
                solidity_code=DEAD_CODE_UNREACHABLE,
            )
        )
        assert isinstance(result, LogicGatekeeperOutput)
        assert result.is_secure is True  # dead code is a compliance warning, doesn't reject
        assert any("unreachable code" in finding for finding in result.flagged_findings)

    def test_safe_contract_passes(self) -> None:
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="SafeContract.sol",
                solidity_code=SAFE_CONTRACT,
            )
        )
        assert isinstance(result, LogicGatekeeperOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.risk_score == 0.0
        assert result.status == "PASSED"

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_LOGIC_STRICT_MODE", "false")
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="BadModifier.sol",
                solidity_code=VULNERABLE_MODIFIER,
            )
        )
        assert isinstance(result, LogicGatekeeperOutput)
        assert result.is_secure is True
        assert result.status == "WARN_LOGIC_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiLogicGatekeeper()
        result = agent.audit_logic(
            LogicGatekeeperInput(
                file_path="SafeContract.sol",
                solidity_code=SAFE_CONTRACT,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_logic_gatekeeper() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform a strict logic tautology check on the solidity modifiers.",
            context={"file_path": "BadModifier.sol", "solidity_code": VULNERABLE_MODIFIER, "check_level": "STRICT"},
        )
    )
    assert result.success is False
    assert "PiLogicGatekeeper" in result.routed_agent
    assert result.risk_score == 85.0
    assert any("merge wildcard" in anomaly for anomaly in result.anomalies_detected)
