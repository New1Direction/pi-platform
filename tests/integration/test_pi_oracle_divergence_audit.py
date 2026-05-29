"""Integration tests for the PiOracleDivergenceAudit micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_oracle_divergence_audit import (
    PiOracleDivergenceAudit,
    OracleDivergenceInput,
    OracleDivergenceOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_ORACLE_DIV_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Vulnerable Oracle Price Deviation (Divergent Price array)
# =====================================================================
def test_oracle_divergence_vulnerable():
    """Verify that excessive price divergence from benchmark is flagged."""
    agent = PiOracleDivergenceAudit()

    # Price deviates by 5% (105.0 vs benchmark 100.0) which is > limit of 2%
    inp = OracleDivergenceInput(
        file_path="aggregator.sol",
        prices=[105.0],
        benchmarks=[100.0],
        max_deviation_percent=2.0,
        solidity_code=""
    )

    out = agent.audit_divergence(inp)

    assert out.is_secure is False
    assert "asset_feed_0" in out.vulnerable_functions
    assert out.risk_score == 90.0
    assert out.status == "REJECTED_ORACLE_DIVERGENCE"
    assert any("exceeding max deviation limit" in f for f in out.flagged_findings)


# =====================================================================
# Test 2: Compliant Oracle and Mathematical Warning Check
# =====================================================================
def test_oracle_divergence_compliant_and_warning():
    """Verify that compliant prices pass but a simple arithmetic average warning is emitted."""
    agent = PiOracleDivergenceAudit()

    solidity_code = """
    contract PriceFeed {
        function getAveragePrice(uint[] memory prices) public pure returns (uint) {
            uint sum = 0;
            for(uint i=0; i<prices.length; i++) {
                sum += prices[i];
            }
            return sum / prices.length;
        }
    }
    """
    # Price is within 1% of benchmark
    inp = OracleDivergenceInput(
        file_path="aggregator.sol",
        prices=[101.0],
        benchmarks=[100.0],
        max_deviation_percent=2.0,
        solidity_code=solidity_code
    )

    out = agent.audit_divergence(inp)

    # It's secure since price deviation is OK, but mathematical aggregation warning is recorded
    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert any("simple arithmetic average" in f for f in out.flagged_findings)


# =====================================================================
# Test 3: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_oracle_divergence_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiOracleDivergenceAudit resolves majority votes."""
    monkeypatch.setenv("PI_ORACLE_DIV_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["asset_feed_0"],
            "flagged_findings": ["Oracle price deviation is 5.00%"],
            "risk_score": 90.0,
            "status": "REJECTED_ORACLE_DIVERGENCE"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["asset_feed_0"],
            "flagged_findings": ["Oracle price deviation is 5.00%"],
            "risk_score": 90.0,
            "status": "REJECTED_ORACLE_DIVERGENCE"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["asset_feed_0"],
            "flagged_findings": ["Oracle price deviation is 5.00%"],
            "risk_score": 90.0,
            "status": "REJECTED_ORACLE_DIVERGENCE"
        }
    ]

    inp = OrchestratorInput(
        goal="price divergence check to verify oracle manipulation deviations",
        context={
            "file_path": "aggregator.sol",
            "prices": [105.0],
            "benchmarks": [100.0],
            "max_deviation_percent": 2.0,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 90.0
    assert "PiOracleDivergenceAudit" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_ORACLE_DIVERGENCE" in res.output_summary
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"
