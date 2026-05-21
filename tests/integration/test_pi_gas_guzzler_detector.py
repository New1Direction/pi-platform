"""Integration tests for PiGasGuzzlerDetector — dual-use gas optimization and loop auditor."""

import os
import pytest
from pydantic import ValidationError

from pi_micro_agents.pi_gas_guzzler_detector import (
    PiGasGuzzlerDetector,
    GasGuzzlerInput,
    GasGuzzlerOutput,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_LOOP = """
pragma solidity 0.8.24;

contract VulnerableGas {
    address[] public users;

    function distributeTokens() public {
        for (uint256 i = 0; i < users.length; i++) {
            // pay user
        }
    }
}
"""

SAFE_LOOP_CACHED = """
pragma solidity 0.8.24;

contract SafeGas {
    address[] public users;

    function distributeTokens() public {
        uint256 len = users.length;
        for (uint256 i = 0; i < len; i++) {
            // pay user
        }
    }
}
"""

GAS_OPTIMIZATION_STORAGE = """
pragma solidity 0.8.24;

contract StorageGuzzler {
    uint256 public stateVar;

    function iterate() public {
        for (uint256 i = 0; i < 10; i++) {
            stateVar = stateVar + 1;
        }
    }
}
"""

GAS_OPTIMIZATION_MEMORY = """
pragma solidity 0.8.24;

contract MemoryInsteadOfCalldata {
    function processData(uint256[] memory data) public pure returns (uint256) {
        return data.length;
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_GAS_STRICT_MODE", raising=False)


# ── Tests: GasGuzzlerDetector Heuristics ──────────────────────────────────────

class TestGasGuzzlerDetector:

    def test_vulnerable_unbounded_loop_detected(self) -> None:
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="VulnerableGas.sol",
            solidity_code=VULNERABLE_LOOP,
        ))
        assert isinstance(result, GasGuzzlerOutput)
        assert result.is_secure is False
        assert "distributeTokens" in result.vulnerable_functions
        assert any("dynamic array" in finding for finding in result.flagged_findings)
        assert result.risk_score == 80.0
        assert result.status == "REJECTED_GAS_RISK"

    def test_safe_cached_loop_passes(self) -> None:
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="SafeGas.sol",
            solidity_code=SAFE_LOOP_CACHED,
        ))
        assert isinstance(result, GasGuzzlerOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.risk_score == 0.0
        assert result.status == "PASSED"

    def test_storage_loop_optimization_flagged(self) -> None:
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="StorageGuzzler.sol",
            solidity_code=GAS_OPTIMIZATION_STORAGE,
        ))
        assert isinstance(result, GasGuzzlerOutput)
        assert result.is_secure is True  # Optimizations are low risk, won't reject unless strict loop is found
        assert any("storage variables" in finding for finding in result.flagged_findings)

    def test_memory_calldata_optimization_flagged(self) -> None:
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="MemoryInsteadOfCalldata.sol",
            solidity_code=GAS_OPTIMIZATION_MEMORY,
        ))
        assert isinstance(result, GasGuzzlerOutput)
        assert result.is_secure is True
        assert any("calldata" in finding for finding in result.flagged_findings)

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_GAS_STRICT_MODE", "false")
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="VulnerableGas.sol",
            solidity_code=VULNERABLE_LOOP,
        ))
        assert isinstance(result, GasGuzzlerOutput)
        assert result.is_secure is True
        assert result.status == "WARN_GAS_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiGasGuzzlerDetector()
        result = agent.audit_gas(GasGuzzlerInput(
            file_path="SafeGas.sol",
            solidity_code=SAFE_LOOP_CACHED,
        ))
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────

def test_orchestrator_nlp_routing_to_gas_guzzler() -> None:
    orchestrator = PiOrchestrator()
    # Query with gas guzzler keywords
    result = orchestrator.execute_goal(OrchestratorInput(
        goal="Perform a gas optimization audit on the smart contract code.",
        context={
            "file_path": "VulnerableGas.sol",
            "solidity_code": VULNERABLE_LOOP,
            "check_level": "STRICT"
        }
    ))
    # Check that consensus triggered the PiGasGuzzlerDetector agent
    assert result.success is False  # Because it has unbounded loop & strict mode
    assert "PiGasGuzzlerDetector" in result.routed_agent
    assert result.risk_score == 80.0
    assert any("dynamic array" in anomaly for anomaly in result.anomalies_detected)
