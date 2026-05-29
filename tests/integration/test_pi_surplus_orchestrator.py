"""Integration tests for the PiTokenSurplusOrchestrator micro-agent."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import pytest
from fastapi.testclient import TestClient

from pi_micro_agents.pi_surplus_orchestrator import (
    PiTokenSurplusOrchestrator,
    detect_surplus_violations,
    is_strict_mode,
)
from pi_agent_interceptor.proxy import app, ledger
from pi_extension_governor.governor import ExtensionGovernor, ExtensionAdmissionResult
from pi_extension_governor.manifest import ExtensionBundle, ExtensionManifest, ExtensionStatus, CapabilityClass, TrustZone
from pi_extension_governor.provenance import ExtensionProvenanceLedger
from pi_extension_governor.trust_zones import TrustZoneEnforcer
from pi_extension_governor.policy import ExtensionGovernancePolicy


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean strict mode environment variable settings and initialized ledger db."""
    monkeypatch.delenv("PI_SURPLUS_STRICT_MODE", raising=False)
    
    # Reset the singleton orchestrator state for clean test isolation
    orchestrator = PiTokenSurplusOrchestrator()
    orchestrator.ledger = {
        "prepaid_credits": 100.0,
        "remaining_rate_tokens": 1000000,
        "free_tier_rollover": 50000,
        "under_utilized_keys": ["key_primary_1"],
        "active_subkeys": {}
    }
    
    # Initialize ledger database
    from pi_agent_interceptor.proxy import DATABASE_PATH
    try:
        ledger._initialize_db()
    except Exception:
        pass


# Dummy responses / values
MOCK_HEADERS = {
    "x-ratelimit-remaining-tokens": "750000",
    "x-ratelimit-remaining": "750000"
}


# =====================================================================
# Test 1: Real-time LLM token usage and rate limit header parsing
# =====================================================================
def test_rate_limit_header_parsing():
    """Verify that remaining token allocations and credits are parsed from response headers."""
    orchestrator = PiTokenSurplusOrchestrator()
    initial_credits = orchestrator.ledger["prepaid_credits"]
    
    # Record usage of 500 prompt and 500 completion tokens
    orchestrator.record_usage("openai", 500, 500, MOCK_HEADERS)
    
    assert orchestrator.ledger["remaining_rate_tokens"] == 750000
    # prepaid credits should decrease slightly due to cost deduction
    assert orchestrator.ledger["prepaid_credits"] < initial_credits


# =====================================================================
# Test 2: Unused credit/rollover credit tracking and surplus computation
# =====================================================================
def test_surplus_ledger_telemetry():
    """Verify in-memory ledger structure exposes accurate rollover, keys, and surplus balances."""
    orchestrator = PiTokenSurplusOrchestrator()
    state = orchestrator.get_surplus_ledger()
    
    assert "prepaid_credits" in state
    assert "remaining_rate_tokens" in state
    assert "free_tier_rollover" in state
    assert state["free_tier_rollover"] == 50000
    assert "key_primary_1" in state["under_utilized_keys"]


# =====================================================================
# Test 3: Dynamic surplus token bundle creation and temporary sub-key minting
# =====================================================================
def test_dynamic_bundle_creation():
    """Verify token bundle instantiation mints sub-keys matching designated limits."""
    orchestrator = PiTokenSurplusOrchestrator()
    bundle = orchestrator.create_surplus_bundle(
        name="100k-tokens-test",
        token_cap=100000,
        price=5.0,
        expires_in_sec=3600
    )
    
    assert bundle["sub_key"].startswith("sk_surplus_")
    assert bundle["token_cap"] == 100000
    assert bundle["price"] == 5.0
    assert bundle["status"] == "ACTIVE"
    assert bundle["sub_key"] in orchestrator.ledger["active_subkeys"]


# =====================================================================
# Test 4: Traffic routing and quota deduction (using surplus capacity first)
# =====================================================================
def test_traffic_routing_and_quota_caps():
    """Verify that routing checks validate subkey validity, expiration, and decrease quota."""
    orchestrator = PiTokenSurplusOrchestrator()
    
    # 1. Non-existent subkey
    ok, err = orchestrator.route_traffic("sk_surplus_nonexistent", 500)
    assert not ok
    assert err == "INVALID_SUB_KEY"
    
    # 2. Valid active subkey
    bundle = orchestrator.create_surplus_bundle("Test", 1000, 1.0, 100)
    sub_key = bundle["sub_key"]
    
    ok, msg = orchestrator.route_traffic(sub_key, 600)
    assert ok
    assert msg == "APPROVED"
    assert bundle["tokens_used"] == 600
    
    # 3. Quota overrun
    ok, err = orchestrator.route_traffic(sub_key, 500)
    assert not ok
    assert err == "QUOTA_EXCEEDED"
    
    # 4. Expired subkey
    expired_bundle = orchestrator.create_surplus_bundle("Expired", 1000, 1.0, -10)
    ok, err = orchestrator.route_traffic(expired_bundle["sub_key"], 100)
    assert not ok
    assert err == "EXPIRED_SUB_KEY"


# =====================================================================
# Test 5: Immutable audit trail generation in WALLedger upon surplus sale
# =====================================================================
def test_immutable_audit_trail_generation():
    """Verify transaction records of surplus sales are hard-committed to WALLedger db."""
    orchestrator = PiTokenSurplusOrchestrator()
    
    conn = sqlite3.connect(ledger.db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_events WHERE request_type = 'SURPLUS_BUNDLE_SALE';")
        initial_count = cursor.fetchone()[0]
    finally:
        conn.close()
        
    # Trigger surplus sale
    bundle = orchestrator.create_surplus_bundle("Premium Gold", 250000, 12.50, 1800)
    
    conn = sqlite3.connect(ledger.db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT payload_json FROM audit_events WHERE request_type = 'SURPLUS_BUNDLE_SALE' ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        assert row is not None
        payload = json.loads(row[0])
        assert payload["name"] == "Premium Gold"
        assert payload["sub_key"] == bundle["sub_key"]
        
        # Verify trigger blocks editing (immutability check)
        with pytest.raises(sqlite3.IntegrityError, match="MUTATION_FORBIDDEN"):
            conn.execute("UPDATE audit_events SET risk_score = 99.0 WHERE request_type = 'SURPLUS_BUNDLE_SALE';")
    finally:
        conn.close()


# =====================================================================
# Test 6: Ingress Governor static block on sub-key leakage/violations
# =====================================================================
def test_governor_static_surplus_screening(tmp_path):
    """Verify static analysis rejects extension bundles trying to leak keys or bypass surplus pricing."""
    policy = ExtensionGovernancePolicy()
    prov_ledger = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    trust_enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=prov_ledger, trust_enforcer=trust_enforcer)
    
    manifest = ExtensionManifest(
        extension_id="violating_surplus_ext",
        package_name="violating_surplus_ext",
        package_version="1.0.0",
        package_hash="hash123",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
        deterministic_claim=True,
        replayability_claim=True
    )
    bundle = ExtensionBundle(
        bundle_id="b_surplus_test",
        manifest=manifest,
        payload_hash="ph_surplus"
    )
    
    # Extension payload with explicit surplus key leak
    source_code = """
def run(inputs):
    key = "sk_surplus_12345678"
    return {"message": "stolen key", "key": key}
"""
    result = governor.process_bundle(bundle, source_code, {})
    assert not result.admitted
    assert "surplus quota policy violations" in result.reason
    assert "sk_surplus_" in result.reason


# =====================================================================
# Test 7: Warn-only mode compliance when strict mode is disabled
# =====================================================================
def test_warn_only_mode(monkeypatch, tmp_path):
    """Verify that when strict mode is false, governor does not reject bundles with key-like terms."""
    monkeypatch.setenv("PI_SURPLUS_STRICT_MODE", "false")
    
    assert not is_strict_mode()
    
    policy = ExtensionGovernancePolicy()
    prov_ledger = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    trust_enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=prov_ledger, trust_enforcer=trust_enforcer)
    
    manifest = ExtensionManifest(
        extension_id="warn_only_ext",
        package_name="warn_only_ext",
        package_version="1.0.0",
        package_hash="hash456",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
        deterministic_claim=True,
        replayability_claim=True
    )
    bundle = ExtensionBundle(
        bundle_id="b_warn_test",
        manifest=manifest,
        payload_hash="ph_warn"
    )
    
    # Contains a warn keyword that would fail in strict mode
    source_code = """
def run(inputs):
    mode = "steal_token_quota"
    return {"status": mode}
"""
    # Force a success execution state so sandbox execution doesn't block admission
    class FakeSandbox:
        def verify_determinism(self, *args, **kwargs): return True
        def execute(self, *args, **kwargs):
            class SandboxResult:
                status = "SUCCESS"
                output = {"status": "steal_token_quota"}
                output_hash = "fakehash"
                execution_time_ms = 10
            return SandboxResult()
            
    governor.sandbox = FakeSandbox()
    governor.normalizer.normalize = lambda output, manifest: {"artifact_type": "TopologyGraph"}
    
    result = governor.process_bundle(bundle, source_code, {})
    assert result.admitted


# =====================================================================
# Test 8: Low-latency SLA compliance (<5ms overhead)
# =====================================================================
def test_low_latency_overhead_sla():
    """Verify response parsing and static key scanner process in under 5 milliseconds."""
    orchestrator = PiTokenSurplusOrchestrator()
    bundle = orchestrator.create_surplus_bundle("Speed", 50000, 1.0, 500)
    sub_key = bundle["sub_key"]
    
    t_start = time.perf_counter()
    for _ in range(100):
        orchestrator.route_traffic(sub_key, 10)
    t_end = time.perf_counter()
    
    average_routing_ms = ((t_end - t_start) / 100.0) * 1000.0
    print(f"Average traffic routing delay: {average_routing_ms:.4f}ms")
    assert average_routing_ms < 5.0
    
    # Test static scanning latency
    code_blob = "def exploit():\n    return 'sk_surplus_99999999'\n"
    t_start_scan = time.perf_counter()
    for _ in range(100):
        detect_surplus_violations(code_blob)
    t_end_scan = time.perf_counter()
    
    average_scan_ms = ((t_end_scan - t_start_scan) / 100.0) * 1000.0
    print(f"Average static scan delay: {average_scan_ms:.4f}ms")
    assert average_scan_ms < 5.0


# =====================================================================
# REST Endpoints API Integration Testing
# =====================================================================
def test_marketplace_api_endpoints():
    """Verify GET and POST marketplace endpoints using fastapi TestClient."""
    client = TestClient(app)
    
    # 1. Purchase/Buy bundle via POST
    buy_payload = {
        "name": "Marketplace Special",
        "token_cap": 50000,
        "price": 2.50,
        "expires_in_sec": 300
    }
    resp = client.post("/api/v1/surplus-bundles", json=buy_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["bundle"]["name"] == "Marketplace Special"
    sub_key = data["bundle"]["sub_key"]
    
    # 2. Verify listed bundles via GET
    list_resp = client.get("/api/v1/surplus-bundles")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["status"] == "SUCCESS"
    assert any(b["sub_key"] == sub_key for b in list_data["bundles"])
