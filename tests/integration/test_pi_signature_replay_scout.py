"""Integration tests for the PiSignatureReplayScout micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_signature_replay_scout import (
    PiSignatureReplayScout,
    SignatureInput,
    SignatureOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_SIGNATURE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable ecrecover usage (no nonces or chainId tracking)
# =====================================================================
def test_signature_vulnerable_contract():
    """Verify that a contract utilizing raw ecrecover without nonces/chainId is flagged."""
    agent = PiSignatureReplayScout()

    solidity_code = """
    pragma solidity ^0.8.0;

    contract VulnerableSig {
        mapping(address => uint256) public balances;

        function transferSigned(
            address from,
            address to,
            uint256 amount,
            bytes32 r,
            bytes32 s,
            uint8 v
        ) public {
            bytes32 messageHash = keccak256(abi.encodePacked(from, to, amount));
            bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", messageHash));
            
            // Vulnerable ecrecover signature check (allows replay attacks)
            address signer = ecrecover(ethSignedMessageHash, v, r, s);
            require(signer == from, "Invalid signature");

            balances[from] -= amount;
            balances[to] += amount;
        }
    }
    """
    inp = SignatureInput(
        file_path="VulnerableSig.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_signature(inp)

    assert out.is_secure is False
    assert "transferSigned" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_SIGNATURE_REPLAY_VULNERABILITY"
    assert len(out.flagged_findings) >= 1
    assert "without references to EIP-712 structured data hashing" in out.flagged_findings[0]


# =====================================================================
# Test 2: Secure EIP-712 Compliant Signature Verification
# =====================================================================
def test_signature_compliant_contract():
    """Verify that a contract utilizing standard EIP-712 domain separators and structured data checks passes."""
    agent = PiSignatureReplayScout()

    solidity_code = """
    pragma solidity ^0.8.0;

    contract CompliantSig {
        bytes32 public DOMAIN_SEPARATOR;
        mapping(address => uint256) public nonces;

        constructor() {
            DOMAIN_SEPARATOR = keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes("CompliantSig")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(this)
                )
            );
        }

        function verify(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
            // Safe ecrecover usage using EIP-712 standards
            address recovered = ecrecover(hash, v, r, s);
            return recovered == signer;
        }
    }
    """
    inp = SignatureInput(
        file_path="CompliantSig.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_signature(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_signature_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiSignatureReplayScout resolves majority votes."""
    monkeypatch.setenv("PI_SIGNATURE_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    pragma solidity ^0.8.0;
    contract Vuln {
        function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (address) {
            return ecrecover(hash, v, r, s);
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["verify"],
            "flagged_findings": ["Function verify recovers signature"],
            "risk_score": 95.0,
            "status": "REJECTED_SIGNATURE_REPLAY_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["verify"],
            "flagged_findings": ["Function verify recovers signature"],
            "risk_score": 95.0,
            "status": "REJECTED_SIGNATURE_REPLAY_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["verify"],
            "flagged_findings": ["Function verify recovers signature"],
            "risk_score": 95.0,
            "status": "REJECTED_SIGNATURE_REPLAY_VULNERABILITY"
        }
    ]

    inp = OrchestratorInput(
        goal="signature replay check on Vuln.sol to verify replay vectors",
        context={
            "file_path": "Vuln.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 95.0
    assert "PiSignatureReplayScout" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_SIGNATURE_REPLAY_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
