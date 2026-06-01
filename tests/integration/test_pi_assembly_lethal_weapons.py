"""Integration tests for PiAssemblyLethalWeapons — dual-use Yul and inline assembly auditor."""

import pytest

from pi_micro_agents.pi_assembly_lethal_weapons import (
    AssemblySafetyInput,
    AssemblySafetyOutput,
    PiAssemblyLethalWeapons,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_ASSEMBLY = """
pragma solidity 0.8.24;

contract UnsafeAssembly {
    function overwriteMemory() public pure {
        assembly {
            mstore(0x40, 256) // raw overwrite of free memory pointer without allocation
        }
    }
}
"""

SAFE_ASSEMBLY_WITH_COMMENT = """
pragma solidity 0.8.24;

contract SafeAssembly {
    function safeMemory() public pure {
        assembly {
            let allocateMemory := 0
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 32))
        }
    }
}
"""

ASSEMBLY_DIV_OPTIMIZATION = """
pragma solidity 0.8.24;

contract AssemblyDivOpt {
    function divide(uint256 val) public pure returns (uint256 res) {
        assembly {
            res := div(val, 2)
        }
    }
}
"""

ASSEMBLY_MUL_OPTIMIZATION = """
pragma solidity 0.8.24;

contract AssemblyMulOpt {
    function multiply(uint256 val) public pure returns (uint256 res) {
        assembly {
            res := mul(val, 4)
        }
    }
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_ASSEMBLY_STRICT_MODE", raising=False)


# ── Tests: AssemblyLethalWeapons Heuristics ───────────────────────────────────


class TestAssemblyLethalWeapons:
    def test_vulnerable_memory_overwrite_detected(self) -> None:
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="UnsafeAssembly.sol",
                solidity_code=VULNERABLE_ASSEMBLY,
            )
        )
        assert isinstance(result, AssemblySafetyOutput)
        assert result.is_secure is False
        assert "overwriteMemory" in result.vulnerable_functions
        assert any("free memory pointer" in finding for finding in result.flagged_findings)
        assert result.risk_score == 90.0
        assert result.status == "REJECTED_ASSEMBLY_RISK"

    def test_safe_assembly_with_proper_allocation_passes(self) -> None:
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="SafeAssembly.sol",
                solidity_code=SAFE_ASSEMBLY_WITH_COMMENT,
            )
        )
        assert isinstance(result, AssemblySafetyOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.risk_score == 0.0
        assert result.status == "PASSED"

    def test_division_by_power_of_two_flagged(self) -> None:
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="AssemblyDivOpt.sol",
                solidity_code=ASSEMBLY_DIV_OPTIMIZATION,
            )
        )
        assert isinstance(result, AssemblySafetyOutput)
        assert result.is_secure is True
        assert any("shr" in finding for finding in result.flagged_findings)

    def test_multiplication_by_power_of_two_flagged(self) -> None:
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="AssemblyMulOpt.sol",
                solidity_code=ASSEMBLY_MUL_OPTIMIZATION,
            )
        )
        assert isinstance(result, AssemblySafetyOutput)
        assert result.is_secure is True
        assert any("shl" in finding for finding in result.flagged_findings)

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_ASSEMBLY_STRICT_MODE", "false")
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="UnsafeAssembly.sol",
                solidity_code=VULNERABLE_ASSEMBLY,
            )
        )
        assert isinstance(result, AssemblySafetyOutput)
        assert result.is_secure is True
        assert result.status == "WARN_ASSEMBLY_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiAssemblyLethalWeapons()
        result = agent.audit_assembly(
            AssemblySafetyInput(
                file_path="SafeAssembly.sol",
                solidity_code=SAFE_ASSEMBLY_WITH_COMMENT,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_assembly_safety() -> None:
    orchestrator = PiOrchestrator()
    # Query with assembly safety keywords
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform inline assembly memory safety check on my Yul blocks.",
            context={"file_path": "UnsafeAssembly.sol", "solidity_code": VULNERABLE_ASSEMBLY, "check_level": "STRICT"},
        )
    )
    assert result.success is False
    assert "PiAssemblyLethalWeapons" in result.routed_agent
    assert result.risk_score == 90.0
    assert any("free memory pointer" in anomaly for anomaly in result.anomalies_detected)
