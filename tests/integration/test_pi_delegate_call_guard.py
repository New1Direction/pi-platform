"""Integration tests for the PiDelegateCallGuard micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_delegate_call_guard import (
    PiDelegateCallGuard,
    DelegateCallInput,
    DelegateCallOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_DELEGATECALL_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Dynamic Delegatecall
# =====================================================================
def test_delegate_call_vulnerable_contract():
    """Verify that a contract utilizing dynamic delegatecalls without EIP-1967 is flagged."""
    agent = PiDelegateCallGuard()

    solidity_code = """
    pragma solidity ^0.8.0;

    contract VulnerableProxy {
        address public implementation;

        function upgradeTo(address newImplementation) public {
            implementation = newImplementation;
        }

        fallback() external payable {
            address impl = implementation;
            assembly {
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
    }
    """
    inp = DelegateCallInput(
        file_path="VulnerableProxy.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_delegatecall(inp)

    assert out.is_secure is False
    assert "fallback" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_DELEGATECALL_VULNERABILITY"
    assert len(out.flagged_findings) >= 1
    assert "without references to the standard EIP-1967 storage slot" in out.flagged_findings[0]


# =====================================================================
# Test 2: Secure EIP-1967 Compliant Proxy
# =====================================================================
def test_delegate_call_compliant_proxy():
    """Verify that a contract utilizing standard EIP-1967 storage slots passes security checks."""
    agent = PiDelegateCallGuard()

    solidity_code = """
    pragma solidity ^0.8.0;

    contract CompliantProxy {
        // EIP-1967 storage slot for implementation address
        bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

        fallback() external payable {
            bytes32 slot = _IMPLEMENTATION_SLOT;
            address impl;
            assembly {
                impl := sload(slot)
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
                returndatacopy(0, 0, returndatasize())
                switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
            }
        }
    }
    """
    inp = DelegateCallInput(
        file_path="CompliantProxy.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_delegatecall(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_delegatecall_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiDelegateCallGuard resolves majority votes."""
    monkeypatch.setenv("PI_DELEGATECALL_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Vuln {
        fallback() external payable {
            address impl;
            assembly {
                let res := delegatecall(gas(), impl, 0, 0, 0, 0)
            }
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["fallback"],
            "flagged_findings": ["Function fallback executes delegatecall"],
            "risk_score": 95.0,
            "status": "REJECTED_DELEGATECALL_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["fallback"],
            "flagged_findings": ["Function fallback executes delegatecall"],
            "risk_score": 95.0,
            "status": "REJECTED_DELEGATECALL_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["fallback"],
            "flagged_findings": ["Function fallback executes delegatecall"],
            "risk_score": 95.0,
            "status": "REJECTED_DELEGATECALL_VULNERABILITY"
        }
    ]

    inp = OrchestratorInput(
        goal="delegatecall scan on Vuln.sol to verify upgrade safety",
        context={
            "file_path": "Vuln.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 95.0
    assert "PiDelegateCallGuard" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_DELEGATECALL_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
