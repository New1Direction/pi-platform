"""Integration tests for PiExternalContractGuard — dual-use external call and zero-address linter."""

import pytest

from pi_micro_agents.pi_external_contract_guard import (
    ExternalContractGuardInput,
    ExternalContractGuardOutput,
    PiExternalContractGuard,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_ADDRESS_SETTER = """
pragma solidity 0.8.24;

contract UnsafeExternalSetter {
    address public trustedBridge;

    function setBridge(address _bridge) public {
        _bridge = trustedBridge;
    }
}
"""

VULNERABLE_RAW_TRANSFER = """
pragma solidity 0.8.24;

contract VulnerableTransfer {
    function withdraw(address token, address recipient, uint256 amount) public {
        IERC20(token).transfer(recipient, amount); // raw transfer without return validation
    }
}
"""

SAFE_EXTERNAL_SETTER = """
pragma solidity 0.8.24;

contract SafeExternalSetter {
    address public trustedBridge;

    function setBridge(address _bridge) public {
        require(_bridge != address(0), "Invalid bridge address");
        trustedBridge = _bridge;
    }
}
"""

SAFE_TRANSFER_WRAPPER = """
pragma solidity 0.8.24;

contract SafeTransfer {
    using SafeERC20 for IERC20;

    function withdraw(address token, address recipient, uint256 amount) public {
        IERC20(token).safeTransfer(recipient, amount);
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_EXTERNAL_STRICT_MODE", raising=False)


# ── Tests: ExternalContractGuard Heuristics ─────────────────────────────────


class TestExternalContractGuard:
    def test_vulnerable_address_setter_detected(self) -> None:
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="UnsafeExternalSetter.sol",
                solidity_code=VULNERABLE_ADDRESS_SETTER,
            )
        )
        assert isinstance(result, ExternalContractGuardOutput)
        assert result.is_secure is False
        assert "setBridge" in result.vulnerable_functions
        assert any("address(0)" in finding for finding in result.flagged_findings)
        assert result.risk_score == 80.0
        assert result.status == "REJECTED_EXTERNAL_RISK"

    def test_raw_transfer_warning_flagged(self) -> None:
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="VulnerableTransfer.sol",
                solidity_code=VULNERABLE_RAW_TRANSFER,
            )
        )
        assert isinstance(result, ExternalContractGuardOutput)
        assert result.is_secure is True  # transfer warning is low risk, doesn't reject
        assert any("SafeERC20" in finding or "return value" in finding for finding in result.flagged_findings)

    def test_safe_setter_passes(self) -> None:
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="SafeExternalSetter.sol",
                solidity_code=SAFE_EXTERNAL_SETTER,
            )
        )
        assert isinstance(result, ExternalContractGuardOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_safe_transfer_passes(self) -> None:
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="SafeTransfer.sol",
                solidity_code=SAFE_TRANSFER_WRAPPER,
            )
        )
        assert isinstance(result, ExternalContractGuardOutput)
        assert result.is_secure is True
        # Should not flag safeTransfer
        assert not any("raw ERC-20 transfer" in finding for finding in result.flagged_findings)

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_EXTERNAL_STRICT_MODE", "false")
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="UnsafeExternalSetter.sol",
                solidity_code=VULNERABLE_ADDRESS_SETTER,
            )
        )
        assert isinstance(result, ExternalContractGuardOutput)
        assert result.is_secure is True
        assert result.status == "WARN_EXTERNAL_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiExternalContractGuard()
        result = agent.audit_external(
            ExternalContractGuardInput(
                file_path="SafeExternalSetter.sol",
                solidity_code=SAFE_EXTERNAL_SETTER,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_external_guard() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform an untrusted contract scan to check external addresses.",
            context={
                "file_path": "UnsafeExternalSetter.sol",
                "solidity_code": VULNERABLE_ADDRESS_SETTER,
                "check_level": "STRICT",
            },
        )
    )
    assert result.success is False
    assert "PiExternalContractGuard" in result.routed_agent
    assert result.risk_score == 80.0
    assert any("address(0)" in anomaly for anomaly in result.anomalies_detected)
