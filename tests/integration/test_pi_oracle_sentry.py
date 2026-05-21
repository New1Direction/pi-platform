"""Integration tests for the PiOracleSentry micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest
from pydantic import ValidationError

from pi_micro_agents.pi_oracle_sentry import (
    PiOracleSentry,
    OracleSentryInput,
    OracleSentryOutput,
    detect_pricing_anomalies,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_ORACLE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Fair prices with low deviation (Success path)
# =====================================================================
def test_oracle_sentry_fair_price():
    """Verify that a fair price with low deviation passes successfully under strict mode."""
    sentry = PiOracleSentry()

    # ETH fair price is 3000.0. 3010.0 is ~0.33% deviation (< 2.0%)
    inp = OracleSentryInput(token="ETH", chain_id=1, current_observed_price=3010.0, max_deviation_percent=2.0)
    out = sentry.audit_prices(inp)

    assert out.is_secure is True
    assert out.status == "PASSED"
    assert out.deviation_detected_percent < 2.0
    assert len(out.flagged_anomalies) == 0


# =====================================================================
# Test 2: High deviation price triggers block in strict mode
# =====================================================================
def test_oracle_sentry_high_deviation(monkeypatch):
    """Verify that a high deviation price triggers a secure=False block under strict mode."""
    sentry = PiOracleSentry()

    # Observed price 3100.0 is 3.33% deviation (exceeds 2.0%)
    inp = OracleSentryInput(token="ETH", chain_id=1, current_observed_price=3100.0, max_deviation_percent=2.0)
    
    # 1. Normal Strict Mode (Enabled by default)
    out_strict = sentry.audit_prices(inp)
    assert out_strict.is_secure is False
    assert out_strict.status == "REJECTED_PRICE"
    assert any("Price deviation" in viol for viol in out_strict.flagged_anomalies)

    # 2. Non-Strict Mode (Warning only)
    monkeypatch.setenv("PI_ORACLE_STRICT_MODE", "false")
    out_warn = sentry.audit_prices(inp)
    assert out_warn.is_secure is True
    assert out_warn.status == "WARN_PRICE"
    assert len(out_warn.flagged_anomalies) > 0


# =====================================================================
# Test 3: Anomalous prices (negative and zero values)
# =====================================================================
def test_oracle_sentry_pricing_anomalies():
    """Verify that negative or zero prices trigger immediate high-risk blocks."""
    sentry = PiOracleSentry()

    # Zero price
    inp_zero = OracleSentryInput(token="BTC", chain_id=1, current_observed_price=0.0)
    out_zero = sentry.audit_prices(inp_zero)
    assert out_zero.is_secure is False
    assert out_zero.status == "REJECTED_PRICE"
    assert any("zero or negative price detected" in viol for viol in out_zero.flagged_anomalies)

    # Negative price
    inp_neg = OracleSentryInput(token="USDC", chain_id=1, current_observed_price=-1.5)
    out_neg = sentry.audit_prices(inp_neg)
    assert out_neg.is_secure is False
    assert out_neg.status == "REJECTED_PRICE"
    assert any("zero or negative price detected" in viol for viol in out_neg.flagged_anomalies)


# =====================================================================
# Test 4: Dynamic routing to PiOracleSentry via PiOrchestrator
# =====================================================================
def test_orchestrator_routing_to_oracle_sentry(monkeypatch):
    """Verify that PiOrchestrator correctly identifies and routes pricing goals to PiOracleSentry."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    # Goal triggers oracle scan route. Fair price of ETH is 3000.0, observed is 3005.0 (<2.0% dev)
    goal = "Execute price verification check on ETH token on mainnet"
    inp = OrchestratorInput(
        goal=goal,
        context={"token": "ETH", "chain_id": 1, "current_observed_price": 3005.0, "max_deviation_percent": 2.0}
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is True
    assert res.routed_agent == "PiOracleSentry"
    assert res.risk_score == 0.0
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"


# =====================================================================
# Test 5: Consensus High Deviation Block via Orchestrator
# =====================================================================
def test_orchestrator_consensus_high_deviation_block(monkeypatch):
    """Verify that high price deviation triggers a fail-shut response inside PiOrchestrator's consensus run."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    # Goal triggers oracle scan route. Observed price 3150.0 is 5% deviation (>2%)
    goal = "Run oracle scan for ETH"
    inp = OrchestratorInput(
        goal=goal,
        context={"token": "ETH", "chain_id": 1, "current_observed_price": 3150.0, "max_deviation_percent": 2.0}
    )
    res = orchestrator.execute_goal(inp)

    # In strict mode, high risk (90.0) from the majority output will trigger fail-shut block
    assert res.success is False
    assert res.routed_agent == "PiOracleSentry"
    assert res.risk_score == 90.0
    assert len(res.anomalies_detected) > 0
