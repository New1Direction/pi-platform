"""Integration tests for PiDeFiSlippageGuard — dual-use DeFi slippage and swap routing auditor."""

import pytest

from pi_micro_agents.pi_defi_slippage_guard import (
    DeFiSlippageInput,
    DeFiSlippageOutput,
    PiDeFiSlippageGuard,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_ZERO_SLIPPAGE = """
pragma solidity 0.8.24;

contract VulnerableSlippage {
    function executeSwap(uint256 amountIn) public {
        router.swapExactTokensForTokens(
            amountIn,
            0,
            path,
            msg.sender,
            block.timestamp
        );
    }
}
"""

VULNERABLE_NO_SLIPPAGE_SETTING = """
pragma solidity 0.8.24;

contract VulnerableSlippageSettings {
    function swapTokens(uint256 amountIn) public {
        router.swapExactTokensForTokens(
            amountIn,
            100,
            path,
            msg.sender,
            block.timestamp
        );
    }
}
"""

SAFE_SLIPPAGE = """
pragma solidity 0.8.24;

contract SafeSlippage {
    function executeSwap(uint256 amountIn, uint256 amountOutMin) public {
        router.swapExactTokensForTokens(
            amountIn,
            amountOutMin,
            path,
            msg.sender,
            block.timestamp
        );
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_SLIPPAGE_STRICT_MODE", raising=False)


# ── Tests: DeFiSlippageGuard Heuristics ──────────────────────────────────────


class TestDeFiSlippageGuard:
    def test_vulnerable_zero_slippage_detected(self) -> None:
        agent = PiDeFiSlippageGuard()
        result = agent.audit_slippage(
            DeFiSlippageInput(
                file_path="VulnerableSlippage.sol",
                solidity_code=VULNERABLE_ZERO_SLIPPAGE,
            )
        )
        assert isinstance(result, DeFiSlippageOutput)
        assert result.is_secure is False
        assert "executeSwap" in result.vulnerable_functions
        assert any("minimum output" in finding for finding in result.flagged_findings)
        assert result.risk_score == 90.0
        assert result.status == "REJECTED_SLIPPAGE_RISK"

    def test_vulnerable_slippage_setting_warning(self) -> None:
        agent = PiDeFiSlippageGuard()
        result = agent.audit_slippage(
            DeFiSlippageInput(
                file_path="VulnerableSlippageSettings.sol",
                solidity_code=VULNERABLE_NO_SLIPPAGE_SETTING,
            )
        )
        assert isinstance(result, DeFiSlippageOutput)
        # Without dynamic parameter it triggers a finding but is_secure remains True (since no hardcoded 0)
        assert result.is_secure is True
        assert any("does not accept a dynamic" in finding for finding in result.flagged_findings)

    def test_safe_slippage_passes(self) -> None:
        agent = PiDeFiSlippageGuard()
        result = agent.audit_slippage(
            DeFiSlippageInput(
                file_path="SafeSlippage.sol",
                solidity_code=SAFE_SLIPPAGE,
            )
        )
        assert isinstance(result, DeFiSlippageOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_SLIPPAGE_STRICT_MODE", "false")
        agent = PiDeFiSlippageGuard()
        result = agent.audit_slippage(
            DeFiSlippageInput(
                file_path="VulnerableSlippage.sol",
                solidity_code=VULNERABLE_ZERO_SLIPPAGE,
            )
        )
        assert isinstance(result, DeFiSlippageOutput)
        assert result.is_secure is True
        assert result.status == "WARN_SLIPPAGE_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiDeFiSlippageGuard()
        result = agent.audit_slippage(
            DeFiSlippageInput(
                file_path="SafeSlippage.sol",
                solidity_code=SAFE_SLIPPAGE,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_defi_slippage_guard() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform a slippage guard check to avoid front-running sandwich attacks.",
            context={
                "file_path": "VulnerableSlippage.sol",
                "solidity_code": VULNERABLE_ZERO_SLIPPAGE,
                "check_level": "STRICT",
            },
        )
    )
    assert result.success is False
    assert "PiDeFiSlippageGuard" in result.routed_agent
    assert result.risk_score == 90.0
    assert any("minimum output" in anomaly for anomaly in result.anomalies_detected)
