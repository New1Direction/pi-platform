"""Integration tests for the PiReentrancySentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_reentrancy_sentry import (
    PiReentrancySentry,
    ReentrancyInput,
    ReentrancyOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_REENTRANCY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Classical Vulnerable Solidity Contract (EtherStore Reentrancy)
# =====================================================================
def test_reentrancy_sentry_vulnerable_contract():
    """Verify that a classical vulnerable Solidity contract is flagged as insecure."""
    agent = PiReentrancySentry()

    solidity_code = """
    contract EtherStore {
        mapping(address => uint) public balances;

        function withdraw() public {
            uint bal = balances[msg.sender];
            require(bal > 0);

            (bool sent, ) = msg.sender.call{value: bal}("");
            require(sent, "Failed to send Ether");

            balances[msg.sender] = 0;
        }
    }
    """
    inp = ReentrancyInput(
        file_path="EtherStore.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_reentrancy(inp)

    assert out.is_secure is False
    assert "withdraw" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_REENTRANCY"
    assert len(out.flagged_findings) > 0
    assert any("State update" in f and "balances[msg.sender] = 0" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Safe Solidity Contract (Checks-Effects-Interactions Pattern)
# =====================================================================
def test_reentrancy_sentry_safe_contract():
    """Verify that a contract following checks-effects-interactions passes successfully."""
    agent = PiReentrancySentry()

    solidity_code = """
    contract SafeStore {
        mapping(address => uint) public balances;

        function withdraw() public {
            uint bal = balances[msg.sender];
            require(bal > 0);

            // Effect before Interaction
            balances[msg.sender] = 0;

            // Interaction
            (bool sent, ) = msg.sender.call{value: bal}("");
            require(sent, "Failed to send Ether");
        }
    }
    """
    inp = ReentrancyInput(
        file_path="SafeStore.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_reentrancy(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0
    assert len(out.flagged_findings) == 0


# =====================================================================
# Test 3: Solidity Contract with OpenZeppelin nonReentrant Modifier
# =====================================================================
def test_reentrancy_sentry_nonreentrant_modifier():
    """Verify that functions protected by nonReentrant modifier are safely ignored."""
    agent = PiReentrancySentry()

    solidity_code = """
    contract GuardedStore {
        mapping(address => uint) public balances;

        function withdraw() public nonReentrant {
            uint bal = balances[msg.sender];
            require(bal > 0);

            (bool sent, ) = msg.sender.call{value: bal}("");
            require(sent, "Failed to send Ether");

            balances[msg.sender] = 0;
        }
    }
    """
    inp = ReentrancyInput(
        file_path="GuardedStore.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_reentrancy(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0
    assert len(out.flagged_findings) == 0


# =====================================================================
# Test 4: Strict and Warning Mode Behaviors
# =====================================================================
def test_reentrancy_strict_vs_warning_modes(monkeypatch):
    """Verify behavior of reentrancy audits under strict vs warning configurations."""
    agent = PiReentrancySentry()

    solidity_code = """
    contract Vulnerable {
        mapping(address => uint) public balances;
        function withdraw() public {
            msg.sender.call{value: 100}("");
            balances[msg.sender] = 0;
        }
    }
    """
    inp = ReentrancyInput(
        file_path="Vulnerable.sol",
        solidity_code=solidity_code
    )

    # 1. Strict Mode: Reject and is_secure=False
    monkeypatch.setenv("PI_REENTRANCY_STRICT_MODE", "true")
    out_strict = agent.audit_reentrancy(inp)
    assert out_strict.is_secure is False
    assert out_strict.status == "REJECTED_REENTRANCY"

    # 2. Warning Mode: Warn but allow is_secure=True
    monkeypatch.setenv("PI_REENTRANCY_STRICT_MODE", "false")
    out_warn = agent.audit_reentrancy(inp)
    assert out_warn.is_secure is True
    assert out_warn.status == "WARN_REENTRANCY"


# =====================================================================
# Test 5: Dynamic Orchestrator Routing (Success Consensus)
# =====================================================================
def test_orchestrator_routing_to_reentrancy_sentry(monkeypatch):
    """Verify that PiOrchestrator correctly identifies reentrancy goals and executes consensus."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    solidity_code = """
    contract SafeStore {
        mapping(address => uint) public balances;
        function withdraw() public {
            balances[msg.sender] = 0;
            msg.sender.call{value: 100}("");
        }
    }
    """
    goal = "Perform a reentrancy scan on contract.sol"
    inp = OrchestratorInput(
        goal=goal,
        context={
            "file_path": "contract.sol",
            "solidity_code": solidity_code
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is True
    assert res.routed_agent == "PiReentrancySentry"
    assert res.risk_score == 0.0
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"


# =====================================================================
# Test 6: Orchestrator Consensus Divergence Alarm (Fail-Shut)
# =====================================================================
def test_orchestrator_reentrancy_consensus_divergence_alarm(monkeypatch):
    """Verify that inconsistent consensus mock outputs trigger a fail-shut block in the orchestrator."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    # Mock evaluate_consensus to return a broken report
    from pi_semantic_radius.consensus_breaker import PiConsensusBreaker, DivergenceReport
    def mock_evaluate_consensus(self, prompt, responses):
        return DivergenceReport(
            prompt=prompt,
            responses=responses,
            semantic_divergence=85.0,
            structural_divergence=0.0,
            consensus_divergence_score=85.0,
            is_broken=True
        )
    monkeypatch.setattr(PiConsensusBreaker, "evaluate_consensus", mock_evaluate_consensus)

    orchestrator = PiOrchestrator()
    goal = "solidity audit on wallet.sol"
    
    # 3 mock runs with split verdicts or high content divergence
    mock_runs = [
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        },
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["withdraw"],
            "flagged_findings": ["Reentrancy violation"],
            "risk_score": 95.0,
            "status": "REJECTED_REENTRANCY"
        }
    ]

    inp = OrchestratorInput(
        goal=goal,
        context={
            "file_path": "wallet.sol",
            "solidity_code": "contract Wallet {}",
            "mock_consensus_runs": mock_runs
        }
    )

    res = orchestrator.execute_goal(inp)

    # In strict mode, high divergence (or a split vote) triggers fail-shut success=False
    assert res.success is False
    assert res.routed_agent == "PiReentrancySentry"
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "REJECTED_DIVERGENCE_ALARM"
    assert res.result_details["consensus_telemetry"]["divergence_score"] >= 60.0
