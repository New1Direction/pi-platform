"""Integration tests for PiFloatingPragmaSentry — dual-use compiler version auditor."""

import pytest

from pi_micro_agents.pi_floating_pragma_sentry import (
    PiFloatingPragmaSentry,
    PragmaSentryInput,
    PragmaSentryOutput,
)
from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator

# ── Fixtures & Mock Contracts ───────────────────────────────────────────────

VULNERABLE_FLOATING = """
pragma solidity ^0.8.20;

contract FloatingContract {
    // floating compiler version allows compilation with untested versions
}
"""

VULNERABLE_BUGGY_LOCKED = """
pragma solidity 0.8.1;

contract BuggyCompilerContract {
    // compiler version 0.8.1 has severe known bugs
}
"""

VULNERABLE_OUTDATED_LOCKED = """
pragma solidity 0.7.6;

contract OutdatedCompilerContract {
    // compiler version below 0.8.0 is outdated
}
"""

SAFE_LOCKED = """
pragma solidity 0.8.24;

contract SafePragmaContract {
    // safe locked modern stable compiler version
}
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("PI_PRAGMA_STRICT_MODE", raising=False)


# ── Tests: FloatingPragmaSentry Heuristics ───────────────────────────────────


class TestFloatingPragmaSentry:
    def test_vulnerable_floating_pragma_detected(self) -> None:
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="FloatingContract.sol",
                solidity_code=VULNERABLE_FLOATING,
            )
        )
        assert isinstance(result, PragmaSentryOutput)
        assert result.is_secure is False
        assert "file_header" in result.vulnerable_functions
        assert any("floating" in finding for finding in result.flagged_findings)
        assert result.risk_score == 80.0
        assert result.status == "REJECTED_PRAGMA_RISK"

    def test_vulnerable_buggy_compiler_detected(self) -> None:
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="BuggyCompilerContract.sol",
                solidity_code=VULNERABLE_BUGGY_LOCKED,
            )
        )
        assert isinstance(result, PragmaSentryOutput)
        assert result.is_secure is True  # Warning on outdated/buggy version, low risk
        assert any("bug" in finding or "0.8.20" in finding for finding in result.flagged_findings)

    def test_vulnerable_outdated_compiler_detected(self) -> None:
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="OutdatedCompilerContract.sol",
                solidity_code=VULNERABLE_OUTDATED_LOCKED,
            )
        )
        assert isinstance(result, PragmaSentryOutput)
        assert result.is_secure is True
        assert any("outdated" in finding or "0.8.0" in finding for finding in result.flagged_findings)

    def test_safe_locked_pragma_passes(self) -> None:
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="SafePragmaContract.sol",
                solidity_code=SAFE_LOCKED,
            )
        )
        assert isinstance(result, PragmaSentryOutput)
        assert result.is_secure is True
        assert len(result.vulnerable_functions) == 0
        assert result.status == "PASSED"

    def test_warn_only_mode(self, monkeypatch) -> None:
        monkeypatch.setenv("PI_PRAGMA_STRICT_MODE", "false")
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="FloatingContract.sol",
                solidity_code=VULNERABLE_FLOATING,
            )
        )
        assert isinstance(result, PragmaSentryOutput)
        assert result.is_secure is True
        assert result.status == "WARN_PRAGMA_RISK"

    def test_model_dump_and_serialization(self) -> None:
        agent = PiFloatingPragmaSentry()
        result = agent.audit_pragma(
            PragmaSentryInput(
                file_path="SafePragmaContract.sol",
                solidity_code=SAFE_LOCKED,
            )
        )
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["vulnerable_functions"], list)


# ── Tests: Orchestration NLP & Consensus Integration ────────────────────────


def test_orchestrator_nlp_routing_to_pragma_sentry() -> None:
    orchestrator = PiOrchestrator()
    result = orchestrator.execute_goal(
        OrchestratorInput(
            goal="Perform a floating pragma compiler check on solidity header files.",
            context={
                "file_path": "FloatingContract.sol",
                "solidity_code": VULNERABLE_FLOATING,
                "check_level": "STRICT",
            },
        )
    )
    assert result.success is False
    assert "PiFloatingPragmaSentry" in result.routed_agent
    assert result.risk_score == 80.0
    assert any("floating" in anomaly for anomaly in result.anomalies_detected)
