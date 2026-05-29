"""Integration tests for PiUpgradeDefectDetector — dual-use proxy upgradeability defect auditor."""

import os
import pytest
from pydantic import ValidationError

from pi_micro_agents.pi_upgrade_defect_detector import (
    PiUpgradeDefectDetector,
    UpgradeDefectInput,
    UpgradeDefectOutput,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_STORAGE_COLLISION = """
pragma solidity 0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract VulnerableParentUpgradeable is Initializable {
    uint256 public value;

    function initialize(uint256 _value) public initializer {
        value = _value;
    }
}
"""

VULNERABLE_PROXY_CONSTRUCTION = """
pragma solidity 0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract VulnerableProxyConstruction is Initializable {
    uint256 public value = 42;
    uint256[50] private __gap;

    function initialize() public initializer {
        // value was assigned outside initialize
    }
}
"""

SAFE_UPGRADEABLE = """
pragma solidity 0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract SafeUpgradeable is Initializable {
    uint256 public value;
    uint256 public constant MAX_LIMIT = 1000;
    uint256[50] private __gap;

    function initialize(uint256 _value) public initializer {
        value = _value;
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_UPGRADE_STRICT_MODE", raising=False)


# ── Tests: UpgradeDefectDetector Heuristics ───────────────────────────────

class TestUpgradeDefectDetector:

    def test_vulnerable_storage_collision_detected(self) -> None:
        agent = PiUpgradeDefectDetector()
        result = agent.audit_upgrade(UpgradeDefectInput(
            file_path="VulnerableParentUpgradeable.sol",
            solidity_code=VULNERABLE_STORAGE_COLLISION,
        ))
        assert isinstance(result, UpgradeDefectOutput)
        assert result.is_secure is False
        assert "VulnerableParentUpgradeable" in result.vulnerable_functions
        assert any("storage gap" in finding for finding in result.flagged_findings)
        assert result.risk_score == 85.0
        assert result.status == "REJECTED_UPGRADE_RISK"

    def test_vulnerable_proxy_construction_detected(self) -> None:
        agent = PiUpgradeDefectDetector()
        result = agent.audit_upgrade(UpgradeDefectInput(
            file_path="VulnerableProxyConstruction.sol",
            solidity_code=VULNERABLE_PROXY_CONSTRUCTION,
        ))
        assert isinstance(result, UpgradeDefectOutput)
        assert result.is_secure is False
        assert "VulnerableProxyConstruction" in result.vulnerable_functions
        assert any("initializes state variable" in finding for finding in result.flagged_findings)
        assert result.risk_score == 85.0
        assert result.status == "REJECTED_UPGRADE_RISK"

    def test_safe_upgradeable_passes(self) -> None:
        agent = PiUpgradeDefectDetector()
        result = agent.audit_upgrade(UpgradeDefectInput(
            file_path="SafeUpgradeable.sol",
            solidity_code=SAFE_UPGRADEABLE,
        ))
        assert isinstance(result, UpgradeDefectOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_UPGRADE_STRICT_MODE", "false")
        agent = PiUpgradeDefectDetector()
        result = agent.audit_upgrade(UpgradeDefectInput(
            file_path="VulnerableParentUpgradeable.sol",
            solidity_code=VULNERABLE_STORAGE_COLLISION,
        ))
        assert isinstance(result, UpgradeDefectOutput)
        assert result.is_secure is True
        assert result.status == "WARN_UPGRADE_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiUpgradeDefectDetector()
        result = agent.audit_upgrade(UpgradeDefectInput(
            file_path="SafeUpgradeable.sol",
            solidity_code=SAFE_UPGRADEABLE,
        ))
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────

def test_orchestrator_nlp_routing_to_upgrade_detector() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(OrchestratorInput(
        goal="Perform a storage collision scan on upgradeable contracts.",
        context={
            "file_path": "VulnerableParentUpgradeable.sol",
            "solidity_code": VULNERABLE_STORAGE_COLLISION,
            "check_level": "STRICT"
        }
    ))
    assert result.success is False
    assert "PiUpgradeDefectDetector" in result.routed_agent
    assert result.risk_score == 85.0
    assert any("storage gap" in anomaly for anomaly in result.anomalies_detected)
