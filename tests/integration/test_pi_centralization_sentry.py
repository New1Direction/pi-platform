"""Integration tests for PiCentralizationSentry — dual-use centralization risk linter."""

import os
import pytest
from pydantic import ValidationError

from pi_micro_agents.pi_centralization_sentry import (
    PiCentralizationSentry,
    CentralizationInput,
    CentralizationOutput,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_CENTRALIZATION = """
pragma solidity 0.8.24;

contract CentralizedContract {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        // instant minting without timelock or multisig consensus
    }
}
"""

VULNERABLE_TIMELOCK = """
pragma solidity 0.8.24;

contract VulnerableTimelock {
    uint256 public delay;

    function setDelay(uint256 newDelay) public {
        require(newDelay < 10 days, "Too long");
        delay = newDelay;
    }
}
"""

SAFE_CENTRALIZATION = """
pragma solidity 0.8.24;

contract SafeDecentralized {
    address public timelock;

    function mint(address to, uint256 amount) public {
        require(msg.sender == timelock, "Only timelock execution allowed");
        // proposal must be approved via multisig consensus
    }
}
"""

SAFE_TIMELOCK = """
pragma solidity 0.8.24;

contract SafeTimelock {
    uint256 public delay;

    function setDelay(uint256 newDelay) public {
        require(newDelay >= 2 days, "Delay too short");
        delay = newDelay;
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_CENTRALIZATION_STRICT_MODE", raising=False)


# ── Tests: CentralizationSentry Heuristics ───────────────────────────────────

class TestCentralizationSentry:

    def test_vulnerable_centralization_detected(self) -> None:
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="CentralizedContract.sol",
            solidity_code=VULNERABLE_CENTRALIZATION,
        ))
        assert isinstance(result, CentralizationOutput)
        assert result.is_secure is False
        assert "mint" in result.vulnerable_functions
        assert any("timelock" in finding or "multi-signature" in finding for finding in result.flagged_findings)
        assert result.risk_score == 80.0
        assert result.status == "REJECTED_CENTRALIZATION_RISK"

    def test_vulnerable_timelock_delay_warning(self) -> None:
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="VulnerableTimelock.sol",
            solidity_code=VULNERABLE_TIMELOCK,
        ))
        assert isinstance(result, CentralizationOutput)
        assert result.is_secure is True  # timelock floor warning is low risk
        assert any("minimum floor" in finding for finding in result.flagged_findings)

    def test_safe_centralization_passes(self) -> None:
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="SafeDecentralized.sol",
            solidity_code=SAFE_CENTRALIZATION,
        ))
        assert isinstance(result, CentralizationOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_safe_timelock_passes(self) -> None:
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="SafeTimelock.sol",
            solidity_code=SAFE_TIMELOCK,
        ))
        assert isinstance(result, CentralizationOutput)
        assert result.is_secure is True
        # Should not flag correct minimum floor
        assert not any("minimum floor" in finding for finding in result.flagged_findings)

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_CENTRALIZATION_STRICT_MODE", "false")
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="CentralizedContract.sol",
            solidity_code=VULNERABLE_CENTRALIZATION,
        ))
        assert isinstance(result, CentralizationOutput)
        assert result.is_secure is True
        assert result.status == "WARN_CENTRALIZATION_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiCentralizationSentry()
        result = agent.audit_centralization(CentralizationInput(
            file_path="SafeTimelock.sol",
            solidity_code=SAFE_TIMELOCK,
        ))
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────

def test_orchestrator_nlp_routing_to_centralization_sentry() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(OrchestratorInput(
        goal="Perform a centralization risk audit and verify timelock setups.",
        context={
            "file_path": "CentralizedContract.sol",
            "solidity_code": VULNERABLE_CENTRALIZATION,
            "check_level": "STRICT"
        }
    ))
    assert result.success is False
    assert "PiCentralizationSentry" in result.routed_agent
    assert result.risk_score == 80.0
    assert any("timelock" in anomaly for anomaly in result.anomalies_detected)
