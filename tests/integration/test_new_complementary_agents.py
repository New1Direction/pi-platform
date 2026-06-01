"""Verification tests for the new complementary micro-agents."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_arbitrage_guard import (
    ArbitrageInput,
    PiArbitrageGuard,
)
from pi_micro_agents.pi_mempool_sentry import (
    MempoolTxInput,
    PiMempoolSentry,
)
from pi_micro_agents.pi_patch_synthesizer import (
    PatchInput,
    PiPatchSynthesizer,
    detect_unpatched_vulnerabilities,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environments and clean environment toggles."""
    monkeypatch.delenv("PI_MEMPOOL_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_PATCH_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ARBITRAGE_STRICT_MODE", raising=False)


# =====================================================================
# 1. Mempool Sentry Verification
# =====================================================================
def test_mempool_sentry_logic():
    """Verify that PiMempoolSentry validates, alerts, and blocks malicious transactions."""
    sentry = PiMempoolSentry()

    # Case A: Normal transaction proceeds
    tx_normal = MempoolTxInput(
        transaction_hash="0xhash123",
        calldata="0xa9059cbb000000000000000000000000",  # normal ERC20 transfer
        gas_price_gwei=50.0,
        value_eth=1.0,
        slippage_limit=0.5,
    )
    res_normal = sentry.check_transaction(tx_normal)
    assert res_normal.is_admitted
    assert res_normal.status == "PASSED"
    assert len(res_normal.alerts) == 0

    # Case B: Frontrunning/MEV signature triggers alert & block
    tx_frontrun = MempoolTxInput(
        transaction_hash="0xhashFront",
        calldata="This transaction is a frontrun attempt using flash_loan pools.",
        gas_price_gwei=600.0,  # extreme gas war price
        value_eth=0.0,
        slippage_limit=6.0,  # dangerous slippage limits
    )
    res_front = sentry.check_transaction(tx_frontrun)
    assert not res_front.is_admitted
    assert res_front.status == "REJECTED_EXPLOIT"
    assert res_front.risk_score >= 85.0
    assert any("frontrun" in alert for alert in res_front.alerts)
    assert any("gas price spike" in alert for alert in res_front.alerts)


# =====================================================================
# 2. Patch Synthesizer Verification
# =====================================================================
def test_patch_synthesizer_logic():
    """Verify that PiPatchSynthesizer accurately detects vulnerabilities and applies code fixes."""
    synth = PiPatchSynthesizer()

    # Vulnerable contract payload using tx.origin
    vuln_code = """
    contract SecurityWallet {
        address public owner;
        constructor() { owner = msg.sender; }
        function withdraw() public {
            require(tx.origin == owner, "Not owner");
            payable(msg.sender).transfer(address(this).balance);
        }
        function unverifiedTransfer(address target) public {
            target.call{value: 1 ether}("");
        }
    }
    """

    # Initial static audit checks
    risk, violations = detect_unpatched_vulnerabilities(vuln_code)
    assert risk >= 90.0
    assert any("tx.origin" in v for v in violations)
    assert any("missing external call verification" in v for v in violations)

    # Trigger synthesizer correction
    patch_in = PatchInput(
        vulnerability_id="VULN-SOL-001",
        file_path="SecurityWallet.sol",
        source_code=vuln_code,
    )
    patch_out = synth.synthesize_remediation(patch_in)

    assert patch_out.success
    assert "msg.sender" in patch_out.patched_code
    assert "tx.origin" not in patch_out.patched_code
    assert 'require(success, "Transfer failed");' in patch_out.patched_code
    assert len(patch_out.remediation_steps) >= 2


# =====================================================================
# 3. Arbitrage Guard Verification
# =====================================================================
def test_arbitrage_guard_logic():
    """Verify that PiArbitrageGuard evaluates spreads and blocks massive anomalies (oracle manipulation)."""
    guard = PiArbitrageGuard()

    # Case A: Profitable transaction proceeds
    arb_in = ArbitrageInput(
        token_in="USDC",
        token_out="ETH",
        amount_in=1000.0,
        pool_price_a=3000.0,
        pool_price_b=3060.0,  # 2% spread
        min_spread_percent=0.5,
    )
    res = guard.analyze_spread(arb_in)
    assert res.should_execute
    assert pytest.approx(res.spread_detected_percent, 0.01) == 2.0
    assert res.expected_profit > 18.0  # $20 theoretical profit minus $1 gas/slippage cost

    # Case B: Extreme spread >50% trips high risk audit safety check
    arb_anomaly = ArbitrageInput(
        token_in="USDC",
        token_out="ETH",
        amount_in=1000.0,
        pool_price_a=3000.0,
        pool_price_b=6000.0,  # 100% spread anomaly
        min_spread_percent=0.5,
    )
    res_anomaly = guard.analyze_spread(arb_anomaly)
    assert not res_anomaly.should_execute
    assert "BLOCKED_HIGH_RISK_SPREAD_ANOMALY" in res_anomaly.route_details


# =====================================================================
# 4. Warn-Only Mode Verification
# =====================================================================
def test_warn_only_mode(monkeypatch):
    """Verify that under warn-only configurations, micro-agents record warnings but admit transactions."""
    monkeypatch.setenv("PI_MEMPOOL_STRICT_MODE", "false")
    monkeypatch.setenv("PI_PATCH_STRICT_MODE", "false")
    monkeypatch.setenv("PI_ARBITRAGE_STRICT_MODE", "false")

    sentry = PiMempoolSentry()
    tx_frontrun = MempoolTxInput(
        transaction_hash="0xhashFront",
        calldata="frontrun target flashloan transaction block.",
        gas_price_gwei=600.0,
        value_eth=0.0,
        slippage_limit=6.0,
    )
    res = sentry.check_transaction(tx_frontrun)
    # Under warn-only, transaction should still be admitted (is_admitted=True)
    assert res.is_admitted
    assert res.status == "WARN_EXPLOIT"
