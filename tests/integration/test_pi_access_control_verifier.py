"""Integration tests for the PiAccessControlVerifier micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_access_control_verifier import (
    PiAccessControlVerifier,
    AccessControlInput,
    AccessControlOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_ACCESS_CONTROL_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Classical Missing Modifier Solidity Contract
# =====================================================================
def test_access_control_vulnerable_contract():
    """Verify that a classical vulnerable Solidity contract lacking access control is flagged."""
    agent = PiAccessControlVerifier()

    solidity_code = """
    contract Token {
        mapping(address => uint) public balances;
        uint public totalSupply;

        function mint(address to, uint amount) public {
            totalSupply += amount;
            balances[to] += amount;
        }

        function withdraw() public {
            msg.sender.transfer(address(this).balance);
        }
    }
    """
    inp = AccessControlInput(
        file_path="Token.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_access_control(inp)

    assert out.is_secure is False
    assert "mint" in out.vulnerable_functions
    assert "withdraw" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_ACCESS_CONTROL"
    assert len(out.flagged_findings) >= 2


# =====================================================================
# Test 2: Safe Solidity Contract with Modifiers
# =====================================================================
def test_access_control_safe_contract():
    """Verify that a contract utilizing access modifiers passes successfully."""
    agent = PiAccessControlVerifier()

    solidity_code = """
    contract SecureToken {
        address public owner;
        mapping(address => uint) public balances;
        uint public totalSupply;

        constructor() {
            owner = msg.sender;
        }

        modifier onlyOwner() {
            require(msg.sender == owner, "Not owner");
            _;
        }

        function mint(address to, uint amount) public onlyOwner {
            totalSupply += amount;
            balances[to] += amount;
        }
    }
    """
    inp = AccessControlInput(
        file_path="SecureToken.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_access_control(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0
    assert len(out.flagged_findings) == 0


# =====================================================================
# Test 3: Uninitialized Ownership Detected
# =====================================================================
def test_access_control_uninitialized_owner():
    """Verify that defining an owner variable without constructor or initializer fails."""
    agent = PiAccessControlVerifier()

    solidity_code = """
    contract Uninitialized {
        address public owner;
        
        function setOwner(address newOwner) public onlyOwner {
            owner = newOwner;
        }
    }
    """
    inp = AccessControlInput(
        file_path="Uninitialized.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_access_control(inp)

    assert out.is_secure is False
    assert "contract_structure" in out.vulnerable_functions
    assert any("defines an 'owner' variable but lacks a constructor" in f for f in out.flagged_findings)


# =====================================================================
# Test 4: Privilege Elevation Detected
# =====================================================================
def test_access_control_privilege_elevation():
    """Verify that state updates modifying owner variables in modifierless functions are flagged."""
    agent = PiAccessControlVerifier()

    solidity_code = """
    contract PrivilegeElevator {
        address public owner;
        mapping(address => bool) public isAdmin;

        constructor() {
            owner = msg.sender;
        }

        function becomeAdmin() public {
            isAdmin[msg.sender] = true;
        }
        
        function takeover() public {
            owner = msg.sender;
        }
    }
    """
    inp = AccessControlInput(
        file_path="PrivilegeElevator.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_access_control(inp)

    assert out.is_secure is False
    assert "takeover" in out.vulnerable_functions
    assert "becomeAdmin" in out.vulnerable_functions
    assert any("PrivilegeElevator" in f or "takeover" in f for f in out.flagged_findings)


# =====================================================================
# Test 5: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_access_control_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiAccessControlVerifier resolves low-divergence majority votes."""
    monkeypatch.setenv("PI_ACCESS_CONTROL_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    # Vulnerable token scenario
    solidity_code = """
    contract Token {
        function mint() public {}
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["mint"],
            "flagged_findings": ["Missing modifier on mint"],
            "risk_score": 95.0,
            "status": "REJECTED_ACCESS_CONTROL"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["mint"],
            "flagged_findings": ["Missing modifier on mint"],
            "risk_score": 95.0,
            "status": "REJECTED_ACCESS_CONTROL"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["mint"],
            "flagged_findings": ["Missing modifier on mint"],
            "risk_score": 95.0,
            "status": "REJECTED_ACCESS_CONTROL"
        }
    ]

    inp = OrchestratorInput(
        goal="access check on Token.sol to verify mint limits",
        context={
            "file_path": "Token.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 95.0
    assert "PiAccessControlVerifier" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_ACCESS_CONTROL" in res.output_summary
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"


# =====================================================================
# Test 6: Orchestrator Consensus High Divergence / Split Vote
# =====================================================================
def test_orchestrator_access_control_consensus_failed_divergence(monkeypatch):
    """Verify that split vote high-divergence output triggers fail-shut and blocks execution."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

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

    solidity_code = """
    contract Token {
        function mint() public {}
    }
    """

    # Highly divergent runs
    mock_consensus_runs = [
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["mint"],
            "flagged_findings": ["Missing modifier on mint"],
            "risk_score": 95.0,
            "status": "REJECTED_ACCESS_CONTROL"
        },
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        }
    ]

    inp = OrchestratorInput(
        goal="privilege check on Token.sol",
        context={
            "file_path": "Token.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    # 2/3 agree on is_secure = True, but divergence is high
    # Let's verify consensus gate results
    assert res.success is False
    assert "consensus coordination alarm" in res.output_summary or "REJECTED_DIVERGENCE_ALARM" in res.output_summary
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "REJECTED_DIVERGENCE_ALARM"
    assert res.result_details["consensus_telemetry"]["divergence_score"] >= 60.0
