"""Integration tests for the PiVyperSecScanner micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_vyper_sec_scanner import (
    PiVyperSecScanner,
    VyperScannerInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_VYPER_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Vyper Compiler Version with @nonreentrant
# =====================================================================
def test_vyper_scanner_vulnerable_compiler():
    """Verify that a Vyper contract with a vulnerable compiler version and nonreentrant decorator is flagged."""
    agent = PiVyperSecScanner()

    vyper_code = """
    # @version 0.3.7

    @external
    @nonreentrant("lock")
    def withdraw():
        pass
    """
    inp = VyperScannerInput(file_path="VulnerableVyper.vy", vyper_code=vyper_code, check_level="STRICT")

    out = agent.audit_vyper(inp)

    assert out.is_secure is False
    assert "global_compiler" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_VYPER_VULNERABILITY"
    assert any("compiler version" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Function Lacking Accessibility Decorator
# =====================================================================
def test_vyper_scanner_missing_decorator():
    """Verify that a function lacking @external or @internal is flagged."""
    agent = PiVyperSecScanner()

    vyper_code = """
    # @version 0.3.10

    def internal_helper():
        pass
    """
    inp = VyperScannerInput(file_path="MissingDecorator.vy", vyper_code=vyper_code, check_level="STRICT")

    out = agent.audit_vyper(inp)

    assert out.is_secure is False
    assert "internal_helper" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_VYPER_VULNERABILITY"
    assert any("lacks access control" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Compliant Vyper Contract
# =====================================================================
def test_vyper_scanner_compliant():
    """Verify that a well-structured compliant Vyper contract passes."""
    agent = PiVyperSecScanner()

    vyper_code = """
    # @version 0.3.10

    @external
    @nonreentrant("lock")
    def withdraw():
        pass
    """
    inp = VyperScannerInput(file_path="CompliantVyper.vy", vyper_code=vyper_code, check_level="STRICT")

    out = agent.audit_vyper(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0


# =====================================================================
# Test 4: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_vyper_scanner_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiVyperSecScanner resolves majority votes."""
    monkeypatch.setenv("PI_VYPER_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    vyper_code = """
    # @version 0.3.7
    @external
    @nonreentrant("lock")
    def withdraw():
        pass
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["global_compiler"],
            "flagged_findings": ["Vulnerable compiler version detected"],
            "risk_score": 90.0,
            "status": "REJECTED_VYPER_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["global_compiler"],
            "flagged_findings": ["Vulnerable compiler version detected"],
            "risk_score": 90.0,
            "status": "REJECTED_VYPER_VULNERABILITY",
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["global_compiler"],
            "flagged_findings": ["Vulnerable compiler version detected"],
            "risk_score": 90.0,
            "status": "REJECTED_VYPER_VULNERABILITY",
        },
    ]

    inp = OrchestratorInput(
        goal="vyper scan to check compiler versions",
        context={"file_path": "contract.vy", "vyper_code": vyper_code, "mock_consensus_runs": mock_consensus_runs},
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiVyperSecScanner" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_VYPER_VULNERABILITY" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
