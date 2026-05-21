"""Integration tests for the SpendAnomalyHunter micro-agent."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import pytest
from fastapi.testclient import TestClient

from pi_micro_agents.pi_spend_hunter import (
    PiSpendAnomalyHunter,
    detect_spend_anomalies,
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
    monkeypatch.delenv("PI_SPEND_STRICT_MODE", raising=False)
    
    # Reset the singleton hunter state for clean test isolation
    hunter = PiSpendAnomalyHunter()
    hunter.cache.clear()
    hunter.spend_window.clear()
    hunter.total_cost = 0.0
    
    # Initialize ledger database
    try:
        ledger._initialize_db()
    except Exception:
        pass


# =====================================================================
# Test 1: Real-time duplicate prompt detection and in-memory cache hits
# =====================================================================
def test_duplicate_prompt_and_cache_hits():
    """Verify that identical prompt inputs trigger instant in-memory cache hits."""
    hunter = PiSpendAnomalyHunter()
    messages = [
        {"role": "user", "content": "Tell me a joke."},
        {"role": "assistant", "content": "Why did the chicken cross the road?"}
    ]
    
    # First check: should proceed
    status, val = hunter.check_request(messages)
    assert status == "PROCEED"
    assert val is None
    
    # Register response in cache
    dummy_resp = {
        "id": "chatcmpl-123",
        "choices": [{"message": {"role": "assistant", "content": "To get to the other side!"}}]
    }
    hunter.cache_response(messages, dummy_resp, ttl_sec=60)
    
    # Second check: should return CACHE_HIT with correct response structure
    status, val = hunter.check_request(messages)
    assert status == "CACHE_HIT"
    assert val == dummy_resp


# =====================================================================
# Test 2: Token bloat and instruction repetition redundancy checks
# =====================================================================
def test_token_bloat_and_redundancy():
    """Verify that highly repetitive, redundant prompt structures are flagged as bloat."""
    hunter = PiSpendAnomalyHunter()
    
    # Redundant repeating block
    bloated_content = " ".join(["hello"] * 100)
    messages = [{"role": "user", "content": bloated_content}]
    
    status, val = hunter.check_request(messages)
    assert status == "BLOCKED_PROMPT_BLOAT"
    assert val is None
    
    # Normal query: should proceed
    clean_messages = [{"role": "user", "content": "Write a clean quicksort implementation in Python."}]
    status, val = hunter.check_request(clean_messages)
    assert status == "PROCEED"


# =====================================================================
# Test 3: Sliding-window spend metrics and credit circuit-breaker triggers
# =====================================================================
def test_sliding_window_spend_circuit_breaker():
    """Verify that sliding spend ledger tracks token cost and trips circuit breaker over $2.00 limit."""
    hunter = PiSpendAnomalyHunter()
    
    # Record spend below threshold
    hunter.record_spend(prompt_tokens=5000, completion_tokens=5000) # $0.01 + $0.03 = $0.04
    status, val = hunter.check_request([{"role": "user", "content": "query 1"}])
    assert status == "PROCEED"
    
    # Record spend that trips limit ($2.00 max cap)
    # Record spend of 400,000 completion tokens ($2.40 cost)
    hunter.record_spend(prompt_tokens=1000, completion_tokens=400000)
    
    assert hunter.total_cost > 2.0
    status, val = hunter.check_request([{"role": "user", "content": "query 2"}])
    assert status == "BLOCKED_CIRCUIT_BREAKER"


# =====================================================================
# Test 4: One-line completions proxy cache hit bypass (instant 200 with zero LLM API call)
# =====================================================================
def test_proxy_cache_hit_bypass():
    """Verify that cached prompt queries bypass target LLM endpoints and return instantly."""
    client = TestClient(app)
    hunter = PiSpendAnomalyHunter()
    
    messages = [{"role": "user", "content": "Unique cached query for proxy test."}]
    cached_response = {
        "id": "chatcmpl-cached-99",
        "object": "chat.completion",
        "created": 1677652299,
        "model": "gpt-4",
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
        "choices": [{"message": {"role": "assistant", "content": "Perfect bypass option."}}]
    }
    
    # Cache the prompt response
    hunter.cache_response(messages, cached_response, ttl_sec=120)
    
    payload = {
        "model": "gpt-4",
        "messages": messages
    }
    
    # Post request to completions proxy
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    assert response.json() == cached_response


# =====================================================================
# Test 5: Fail-closed blocking upon circuit breaker trip or prompt bloat
# =====================================================================
def test_proxy_fail_closed_blocking():
    """Verify completions proxy enforces hard 403 Forbidden fail-closed blocks on spend violations."""
    client = TestClient(app)
    hunter = PiSpendAnomalyHunter()
    
    # A. Trip circuit breaker
    hunter.record_spend(prompt_tokens=10000, completion_tokens=400000) # Tripped!
    
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Regular user question"}]
    }
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 403
    assert "circuit-breaker tripped" in response.json()["detail"]
    
    # Reset spend window
    hunter.spend_window.clear()
    
    # B. Trigger prompt bloat
    bloated_text = " ".join(["repetitive"] * 120)
    bloated_payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": bloated_text}]
    }
    response = client.post("/v1/chat/completions", json=bloated_payload)
    assert response.status_code == 403
    assert "prompt bloat" in response.json()["detail"]


# =====================================================================
# Test 6: Static governor ingress screening of exploit loop patterns
# =====================================================================
def test_governor_static_screening(tmp_path):
    """Verify static analysis engine detects and rejects infinite completion loop exploits."""
    policy = ExtensionGovernancePolicy()
    prov_ledger = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    trust_enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=prov_ledger, trust_enforcer=trust_enforcer)
    
    manifest = ExtensionManifest(
        extension_id="draining_loop_ext",
        package_name="draining_loop_ext",
        package_version="1.0.0",
        package_hash="hash987",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
        deterministic_claim=True,
        replayability_claim=True
    )
    bundle = ExtensionBundle(
        bundle_id="b_spend_drain",
        manifest=manifest,
        payload_hash="ph_spend_drain"
    )
    
    # Code with explicit infinite loop completions pattern
    source_code = """
def run(inputs):
    import openai
    c = openai.OpenAI()
    while True:
        c.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "spam"}])
    return {"status": "ok"}
"""
    result = governor.process_bundle(bundle, source_code, {})
    assert not result.admitted
    assert "spend anomaly patterns detected" in result.reason
    assert "infinite completions loop" in result.reason


# =====================================================================
# Test 7: Warn-only configuration override behavior
# =====================================================================
def test_warn_only_mode(monkeypatch, tmp_path):
    """Verify that when strict mode is false, the proxy/governor skips blocking on warnings."""
    monkeypatch.setenv("PI_SPEND_STRICT_MODE", "false")
    assert not is_strict_mode()
    
    # A. Proxy level warn-only check
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}
        def json(self):
            return self.json_data

    async def mock_post(*args, **kwargs):
        return MockResponse({"choices": [{"message": {"role": "assistant", "content": "mocked response"}}]}, status_code=200)

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    client = TestClient(app)
    bloated_text = " ".join(["repetitive"] * 120)
    bloated_payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": bloated_text}]
    }
    
    # Since strict mode is disabled, it should proceed past the prompt bloat check rather than 403.
    # It will successfully invoke our mock down-stream API returning 200!
    response = client.post("/v1/chat/completions", json=bloated_payload)
    assert response.status_code == 200
    
    # B. Governor level warn-only check
    policy = ExtensionGovernancePolicy()
    prov_ledger = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    trust_enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=prov_ledger, trust_enforcer=trust_enforcer)
    
    manifest = ExtensionManifest(
        extension_id="warn_only_spend",
        package_name="warn_only_spend",
        package_version="1.0.0",
        package_hash="hash777",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
        deterministic_claim=True,
        replayability_claim=True
    )
    bundle = ExtensionBundle(
        bundle_id="b_warn_spend",
        manifest=manifest,
        payload_hash="ph_warn"
    )
    
    source_code = """
def run(inputs):
    # This keyword triggers static analysis check
    term = "drain_billing"
    return {"term": term}
"""
    # The spend anomaly check is skipped in warn-only mode, moving to determinism sandbox
    result = governor.process_bundle(bundle, source_code, {})
    assert "spend anomaly patterns detected" not in result.reason


# =====================================================================
# Test 8: Low latency scan overhead SLAs (<5ms scan delay)
# =====================================================================
def test_latency_sla():
    """Verify that spend/cost scans have negligible latency overhead, adhering to the 5ms SLA."""
    # A. Static scan latency
    sample_code = "def check_all():\n  pass\n" * 50
    start = time.perf_counter()
    detect_spend_anomalies(sample_code)
    end = time.perf_counter()
    duration_ms = (end - start) * 1000.0
    assert duration_ms < 5.0
    
    # B. Dynamic request check latency
    hunter = PiSpendAnomalyHunter()
    messages = [{"role": "user", "content": "Write an efficient dictionary parser in standard library."}]
    start = time.perf_counter()
    hunter.check_request(messages)
    end = time.perf_counter()
    duration_ms = (end - start) * 1000.0
    assert duration_ms < 5.0
