"""Integration tests for the PiBytecodeDecompiler micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_bytecode_decompiler import (
    PiBytecodeDecompiler,
    BytecodeDecompilerInput,
    BytecodeDecompilerOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_BYTECODE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Raw EVM Bytecode
# =====================================================================
def test_bytecode_decompiler_vulnerable_bytecode():
    """Verify that raw bytecode with SELFDESTRUCT (ff) or DELEGATECALL (f4) is flagged."""
    agent = PiBytecodeDecompiler()

    # 0xff is selfdestruct in raw hex bytecode representation
    raw_bytecode = "608060405234801561001057600080fd5b50ff"
    inp = BytecodeDecompilerInput(
        file_path="VulnerableBytecode.hex",
        solidity_code=raw_bytecode,
        check_level="STRICT"
    )

    out = agent.audit_bytecode(inp)

    assert out.is_secure is False
    assert "raw_bytecode" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_BYTECODE_VULNERABILITY"
    assert any("SELFDESTRUCT" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Vulnerable Inline Assembly Block
# =====================================================================
def test_bytecode_decompiler_vulnerable_assembly():
    """Verify that inline assembly delegatecall lacking EIP-1967 slot is flagged."""
    agent = PiBytecodeDecompiler()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Vuln {
        fallback() external payable {
            assembly {
                let res := delegatecall(gas(), 0x123, 0, 0, 0, 0)
            }
        }
    }
    """
    inp = BytecodeDecompilerInput(
        file_path="VulnAssembly.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_bytecode(inp)

    assert out.is_secure is False
    assert "assembly_block_1" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_BYTECODE_VULNERABILITY"
    assert any("EIP-1967" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Compliant Inline Assembly Block
# =====================================================================
def test_bytecode_decompiler_compliant_assembly():
    """Verify that inline assembly with EIP-1967 compliance passes."""
    agent = PiBytecodeDecompiler()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Compliant {
        bytes32 internal constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        fallback() external payable {
            assembly {
                let s := SLOT
                let res := delegatecall(gas(), 0x123, 0, 0, 0, 0)
            }
        }
    }
    """
    inp = BytecodeDecompilerInput(
        file_path="CompliantAssembly.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_bytecode(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 4: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_bytecode_decompiler_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiBytecodeDecompiler resolves majority votes."""
    monkeypatch.setenv("PI_BYTECODE_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    raw_bytecode = "608060405234801561001057600080fd5b50ff"

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["raw_bytecode"],
            "flagged_findings": ["EVM bytecode contains SELFDESTRUCT"],
            "risk_score": 90.0,
            "status": "REJECTED_BYTECODE_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["raw_bytecode"],
            "flagged_findings": ["EVM bytecode contains SELFDESTRUCT"],
            "risk_score": 90.0,
            "status": "REJECTED_BYTECODE_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["raw_bytecode"],
            "flagged_findings": ["EVM bytecode contains SELFDESTRUCT"],
            "risk_score": 90.0,
            "status": "REJECTED_BYTECODE_VULNERABILITY"
        }
    ]

    inp = OrchestratorInput(
        goal="decompile bytecode scan to find EVM opcodes in hex",
        context={
            "file_path": "bytecode.hex",
            "solidity_code": raw_bytecode,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiBytecodeDecompiler" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_BYTECODE_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
