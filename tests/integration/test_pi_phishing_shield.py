"""Integration tests for PiPhishingShield — dual-use callback phishing and permit verifier."""

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_phishing_shield import (
    PhishingShieldInput,
    PhishingShieldOutput,
    PiPhishingShield,
)

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_CALLBACK = """
pragma solidity 0.8.24;

contract PhishingCallback {
    address public lastCaller;

    function onTokenTransfer(address sender, uint256 amount, bytes calldata data) public {
        // acts as a callback but uses msg.sender without any validation gates
        lastCaller = msg.sender;
    }
}
"""

VULNERABLE_PERMIT = """
pragma solidity 0.8.24;

contract PermitVulnerable {
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata sig) public {
        // has deadline parameter but doesn't check it against block.timestamp
        address signer = owner;
    }
}
"""

SAFE_CALLBACK = """
pragma solidity 0.8.24;

contract SafeCallback {
    address public tokenAddress;

    constructor(address _token) {
        tokenAddress = _token;
    }

    function onTokenTransfer(address sender, uint256 amount, bytes calldata data) public {
        // callback with strict validation gate
        require(msg.sender == tokenAddress, "Unauthorized token callback");
    }
}
"""

SAFE_PERMIT = """
pragma solidity 0.8.24;

contract SafePermit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata sig) public {
        require(block.timestamp <= deadline, "Permit signature expired");
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_PHISHING_STRICT_MODE", raising=False)


# ── Tests: PhishingShield Heuristics ─────────────────────────────────────────


class TestPhishingShield:
    def test_vulnerable_callback_detected(self) -> None:
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="PhishingCallback.sol",
                solidity_code=VULNERABLE_CALLBACK,
            )
        )
        assert isinstance(result, PhishingShieldOutput)
        assert result.is_secure is False
        assert "onTokenTransfer" in result.vulnerable_functions
        assert any("callback" in finding for finding in result.flagged_findings)
        assert result.risk_score == 85.0
        assert result.status == "REJECTED_PHISHING_RISK"

    def test_vulnerable_permit_deadline_warning(self) -> None:
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="PermitVulnerable.sol",
                solidity_code=VULNERABLE_PERMIT,
            )
        )
        assert isinstance(result, PhishingShieldOutput)
        assert result.is_secure is True  # permit deadline is warning, doesn't reject
        assert any("deadline" in finding for finding in result.flagged_findings)

    def test_safe_callback_passes(self) -> None:
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="SafeCallback.sol",
                solidity_code=SAFE_CALLBACK,
            )
        )
        assert isinstance(result, PhishingShieldOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_safe_permit_passes(self) -> None:
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="SafePermit.sol",
                solidity_code=SAFE_PERMIT,
            )
        )
        assert isinstance(result, PhishingShieldOutput)
        assert result.is_secure is True
        assert len(result.flagged_findings) == 0

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_PHISHING_STRICT_MODE", "false")
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="PhishingCallback.sol",
                solidity_code=VULNERABLE_CALLBACK,
            )
        )
        assert isinstance(result, PhishingShieldOutput)
        assert result.is_secure is True
        assert result.status == "WARN_PHISHING_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiPhishingShield()
        result = agent.audit_phishing(
            PhishingShieldInput(
                file_path="SafePermit.sol",
                solidity_code=SAFE_PERMIT,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_phishing_shield() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform a phishing shield scan and check callback functions.",
            context={
                "file_path": "PhishingCallback.sol",
                "solidity_code": VULNERABLE_CALLBACK,
                "check_level": "STRICT",
            },
        )
    )
    assert result.success is False
    assert "PiPhishingShield" in result.routed_agent
    assert result.risk_score == 85.0
    assert any("callback" in anomaly for anomaly in result.anomalies_detected)
