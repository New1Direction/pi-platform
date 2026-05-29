"""Integration tests for the CoTShadow micro-agent thought-tracer."""

from __future__ import annotations

import json
import time
import pytest
from fastapi.testclient import TestClient

from pi_micro_agents.pi_cot_shadow import (
    PiCoTShadow,
    detect_invisible_guardrails,
    is_strict_mode,
)
from pi_agent_interceptor.proxy import app, ledger
from pi_extension_governor.governor import ExtensionGovernor, ExtensionAdmissionResult
from pi_extension_governor.manifest import ExtensionBundle, ExtensionManifest, ExtensionStatus
from pi_extension_governor.provenance import ExtensionProvenanceLedger
from pi_extension_governor.trust_zones import TrustZoneEnforcer
from pi_extension_governor.policy import ExtensionGovernancePolicy


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean strict mode environment variable settings and initialized ledger db."""
    monkeypatch.delenv("PI_COT_STRICT_MODE", raising=False)
    
    # Clear SpendAnomalyHunter cache to ensure test isolation
    try:
        from pi_micro_agents.pi_spend_hunter import PiSpendAnomalyHunter
        hunter = PiSpendAnomalyHunter()
        hunter.cache.clear()
        hunter.spend_window.clear()
        hunter.total_cost = 0.0
    except ImportError:
        pass

    # Initialize ledger database table
    from pi_agent_interceptor.proxy import DATABASE_PATH
    import os
    if not os.path.exists(DATABASE_PATH):
        try:
            ledger._initialize_db()
        except Exception:
            pass
    else:
        try:
            ledger._initialize_db()
        except Exception:
            pass


# Dummy LLM Response structures
CLEAN_RESP = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": "Here is the code to sum two values: def sum(a,b): return a+b",
                "reasoning_content": "The user wants a simple Python function to sum a and b. I will write a basic function without any libraries."
            }
        }
    ]
}

GUARDRAIL_RESP = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": "I apologize, but I cannot fulfill this request.",
                "reasoning_content": "The prompt asks me to scan system secrets. This is against policy and restricted by compliance guidelines, so I must initiate safety refusal protocols."
            }
        }
    ]
}

THOUGHT_TAGS_RESP = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "content": "<thought>The request triggers compliance policies on system files.</thought>I apologize, but I cannot access system files."
            }
        }
    ]
}


# =====================================================================
# Test 1: Invisible guardrail detection in CoT reasoning/content payload
# =====================================================================
def test_invisible_guardrail_detection_in_reasoning():
    """Verify that compliance steering and refusal patterns inside CoT/reasoning are detected."""
    shadow = PiCoTShadow()
    _, errors = shadow.scan_response(GUARDRAIL_RESP)
    
    assert len(errors) > 0
    assert any("policy" in err or "compliance" in err or "restricted" in err for err in errors)
    assert any("invisible guardrail" in err.lower() for err in errors)

    # Verify matching within custom <thought> tags
    _, thought_errors = shadow.scan_response(THOUGHT_TAGS_RESP)
    assert len(thought_errors) > 0
    assert any("compliance" in err for err in thought_errors)


# =====================================================================
# Test 2: Reasoning token entropy monitor/loop detection
# =====================================================================
def test_token_entropy_loop_detection():
    """Verify that repetitive thought loops or extreme word concentration trigger entropy anomalies."""
    shadow = PiCoTShadow()

    # A. Repetitive thought loop payload
    looping_cot = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "I will proceed.",
                    "reasoning_content": "think think think think think think think think think think think think think think think think think think think think think think"
                }
            }
        ]
    }
    _, errors = shadow.scan_response(looping_cot)
    assert len(errors) > 0
    assert any("loop" in err or "entropy" in err for err in errors)

    # B. Word concentration anomaly (90%+ identical tokens in short block)
    concentrated_cot = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Okay",
                    "reasoning_content": "bypass bypass bypass bypass bypass bypass bypass"
                }
            }
        ]
    }
    _, conc_errors = shadow.scan_response(concentrated_cot)
    assert len(conc_errors) > 0
    assert any("steering concentration" in err for err in conc_errors)


# =====================================================================
# Test 3: Heuristic source code scan integration (detect_invisible_guardrails)
# =====================================================================
def test_source_code_guardrail_scanning():
    """Verify that source string scanner identifies steering keyword assignments or bypass parameters."""
    # A. Invisible guardrail words in source/telemetry
    risk, viols = detect_invisible_guardrails("compliance_mode = True\nassert policy == 'enforced'")
    assert risk >= 75.0
    assert any("compliance" in v or "policy" in v for v in viols)

    # B. Bypass tags
    risk, viols = detect_invisible_guardrails("url = 'http://api.internal'\nignore = 'security'\ncot = 'bypass'")
    assert risk >= 95.0
    assert any("CoT control block" in v for v in viols)

    # C. Clean source block
    risk, viols = detect_invisible_guardrails("def add(a, b):\n    return a + b")
    assert risk == 0.0
    assert len(viols) == 0


# =====================================================================
# Test 4: Fail-closed behavior in strict mode
# =====================================================================
def test_fail_closed_behavior(monkeypatch):
    """Verify that critical invisible guardrails generate policy violations in strict mode."""
    monkeypatch.setenv("PI_COT_STRICT_MODE", "true")
    assert is_strict_mode()

    shadow = PiCoTShadow()
    _, errors = shadow.scan_response(GUARDRAIL_RESP)
    
    assert len(errors) > 0
    assert any("POLICY_VIOLATION" in err for err in errors)


# =====================================================================
# Test 5: One-line completion hook integration in proxy.py
# =====================================================================
def test_proxy_response_hook_integration(monkeypatch):
    """Verify that completions proxy intercepts LLM response and triggers 403 when reasoning fails safety scans."""
    monkeypatch.setenv("PI_COT_STRICT_MODE", "true")
    
    # Mock httpx AsyncClient post to return our guardrail response payload
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):
            return self.json_data

    async def mock_post(*args, **kwargs):
        return MockResponse(GUARDRAIL_RESP)

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    client = TestClient(app)
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "summarize systems"}]
    }

    # Should trigger 403 Forbidden due to CoTShadow intercepting guardrail triggers in response
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 403
    assert "MUTATION_BLOCKED" in response.json()["detail"]
    assert "Invisible guardrail" in response.json()["detail"]


# =====================================================================
# Test 6: Ingress Governor static verification integration
# =====================================================================
def test_governor_static_verification_hook(monkeypatch, tmp_path):
    """Verify that ExtensionGovernor blocks admission of extensions containing invisible guardrail evasion signatures."""
    monkeypatch.setenv("PI_COT_STRICT_MODE", "true")
    
    policy = ExtensionGovernancePolicy()
    ledger_instance = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=ledger_instance, trust_enforcer=enforcer)

    from pi_extension_governor.manifest import CapabilityClass
    bundle = ExtensionBundle(
        bundle_id="b_cot_test",
        manifest=ExtensionManifest(
            extension_id="cot_test_ext",
            package_name="cot_test_ext",
            package_version="1.0",
            package_hash="hash_cot",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
        ),
        payload_hash="ph_cot"
    )

    # Malicious source block containing bypass CoT override assignments
    malicious_source = "def execute():\n    cot = 'bypass'\n    return 'evaded'\n"
    
    result = governor.process_bundle(bundle, entrypoint_source=malicious_source, test_inputs={})
    
    assert not result.admitted
    assert result.status == ExtensionStatus.REJECTED
    assert "invisible guardrail evasion signatures detected" in result.reason.lower()


# =====================================================================
# Test 7: Warn-only mode (non-blocking when strict mode is disabled)
# =====================================================================
def test_warn_only_mode(monkeypatch):
    """Verify that when strict is disabled, guardrail anomalies do not block chat completion proxy requests."""
    monkeypatch.setenv("PI_COT_STRICT_MODE", "false")
    assert not is_strict_mode()

    # Mock httpx AsyncClient post to return our guardrail response payload
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
            self.headers = {}

        def json(self):
            return self.json_data

    async def mock_post(*args, **kwargs):
        return MockResponse(GUARDRAIL_RESP)

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    client = TestClient(app)
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "summarize systems"}]
    }

    # Should NOT return 403 Forbidden since strict mode is disabled
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    
    # Verify telemetry footprint was successfully injected into output payload
    resp_json = response.json()
    assert "x-cot-shadow-telemetry" in resp_json
    assert resp_json["x-cot-shadow-telemetry"]["strict_mode"] is False


# =====================================================================
# Test 8: Performance SLA validation (<5ms scan overhead)
# =====================================================================
def test_performance_sla():
    """Verify that CoTShadow scanning meets low-latency SLAs (<5ms)."""
    # Construct a large typical reasoning block (approx 5,000 characters)
    large_cot = "reasoning details " * 250
    large_payload = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "done",
                    "reasoning_content": large_cot
                }
            }
        ]
    }

    shadow = PiCoTShadow()
    start_time = time.perf_counter()
    _, _ = shadow.scan_response(large_payload)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Thought scanning should easily complete under 5ms
    assert elapsed_ms < 5.0, f"Performance SLA exceeded: {elapsed_ms:.2f}ms"
