"""Integration tests for the SchemaGhost micro-agent shadow parameter scanner."""

from __future__ import annotations

import json
import time

import pytest

from pi_agent_chain.models import DependencyGraph, SemanticField, SemanticIRTrace
from pi_agent_chain.nodes.spec_synthesizer import SpecSynthesizerNode
from pi_extension_governor.governor import ExtensionGovernor
from pi_extension_governor.manifest import ExtensionBundle, ExtensionManifest, ExtensionStatus
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_extension_governor.provenance import ExtensionProvenanceLedger
from pi_extension_governor.trust_zones import TrustZoneEnforcer
from pi_micro_agents.pi_schema_ghost import (
    PiSchemaGhost,
    detect_shadow_parameters,
    is_strict_mode,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean strict mode environment variable settings for consistent testing."""
    monkeypatch.delenv("PI_GHOST_STRICT_MODE", raising=False)


# Dummy spec for schema scanning tests
SAMPLE_SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "Test Spec", "version": "1.0"},
    "paths": {
        "/v1/users": {
            "get": {
                "operationId": "get_users",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    {"name": "debug", "in": "query", "schema": {"type": "boolean"}},
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "user_id": {"type": "string"},
                                        "admin_privilege": {"type": "boolean"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/v1/auth/login": {
            "post": {
                "operationId": "login",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                    "bypass_auth": {"type": "boolean"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
}


# =====================================================================
# Test 1: Shadow parameter detection in OpenAPI schemas
# =====================================================================
def test_shadow_parameter_detection_in_schemas():
    """Verify that shadow parameters in queries, headers, and schemas are scanned and reported."""
    ghost = PiSchemaGhost()
    scanned_dict, errors = ghost.scan(SAMPLE_SPEC)

    assert "x-intent-graph" in scanned_dict
    nodes = scanned_dict["x-intent-graph"]["nodes"]

    # Check that endpoints containing shadow parameters are recognized
    endpoints = {n["id"] for n in nodes}
    assert "GET /v1/users" in endpoints
    assert "POST /v1/auth/login" in endpoints

    # Verify exact parameter matches
    user_node = next(n for n in nodes if n["id"] == "GET /v1/users")
    assert "admin_privilege" in user_node["shadow_parameters"]
    assert "debug" in user_node["shadow_parameters"]

    login_node = next(n for n in nodes if n["id"] == "POST /v1/auth/login")
    assert "bypass_auth" in login_node["shadow_parameters"]


# =====================================================================
# Test 2: Intent Graph construction accuracy
# =====================================================================
def test_intent_graph_construction():
    """Verify that shared shadow parameters across endpoints produce correct edges."""
    spec_with_shared = {
        "openapi": "3.1.0",
        "paths": {
            "/api/endpointA": {"get": {"parameters": [{"name": "debug", "in": "query"}]}},
            "/api/endpointB": {
                "post": {
                    "requestBody": {
                        "content": {"application/json": {"schema": {"properties": {"debug": {"type": "boolean"}}}}}
                    }
                }
            },
        },
    }
    ghost = PiSchemaGhost()
    scanned_dict, _ = ghost.scan(spec_with_shared)

    graph = scanned_dict["x-intent-graph"]
    edges = graph["edges"]

    assert len(edges) == 1
    edge = edges[0]
    assert edge["source"] == "GET /api/endpointA"
    assert edge["target"] == "POST /api/endpointB"
    assert "debug" in edge["shared_parameters"]
    assert edge["relationship_type"] == "shared_shadow_control_plane"


# =====================================================================
# Test 3: Standard source code/text shadow pattern scanning
# =====================================================================
def test_source_code_shadow_scanning():
    """Verify that source string scanner identifies keyword assignments."""
    # A. Assignment patterns
    risk, viols = detect_shadow_parameters("def execute():\n    admin = True\n")
    assert risk >= 90.0
    assert any("admin" in v for v in viols)

    # B. Bypass parameters
    risk, viols = detect_shadow_parameters("url = 'http://api.internal?bypass_mode=1'")
    assert risk >= 90.0
    assert any("bypass" in v for v in viols)

    # C. Clean source block
    risk, viols = detect_shadow_parameters("def execute():\n    user_count = 10\n    return user_count\n")
    assert risk == 0.0
    assert len(viols) == 0


# =====================================================================
# Test 4: Fail-closed behavior in strict mode
# =====================================================================
def test_fail_closed_behavior(monkeypatch):
    """Verify that critical shadow parameters generate policy violations in strict mode."""
    monkeypatch.setenv("PI_GHOST_STRICT_MODE", "true")
    assert is_strict_mode()

    ghost = PiSchemaGhost()
    _, errors = ghost.scan(SAMPLE_SPEC)

    # We should have error violations for 'admin_privilege' and 'bypass_auth'
    assert len(errors) > 0
    assert any("admin_privilege" in err or "bypass_auth" in err for err in errors)
    assert any("POLICY_VIOLATION" in err for err in errors)


# =====================================================================
# Test 5: One-line hook integration in SpecSynthesizerNode
# =====================================================================
def test_synthesizer_node_hook_integration():
    """Verify that SpecSynthesizerNode compiles specs with x-intent-graph successfully."""
    synthesizer = SpecSynthesizerNode()

    # Construct a minimal valid trace
    field = SemanticField(
        path="request.debug",
        inferred_type="BOOLEAN",
        entropy_score=0.1,
        confidence=1.0,
    )
    trace = SemanticIRTrace(
        endpoint_template="/v1/debug",
        method="POST",
        fields=[field],
    )
    graph = DependencyGraph(session_window_id="sess_123")

    spec = synthesizer.synthesize([trace], graph)

    # Assert synthesized specification has x-intent-graph embedded
    assert spec.is_valid
    parsed = json.loads(spec.spec_json)
    assert "x-intent-graph" in parsed
    nodes = parsed["x-intent-graph"]["nodes"]
    assert len(nodes) == 1
    assert nodes[0]["id"] == "POST /v1/debug"
    assert any("debug" in p for p in nodes[0]["shadow_parameters"])


# =====================================================================
# Test 6: Ingress Governor static verification integration
# =====================================================================
def test_governor_static_verification_hook(monkeypatch, tmp_path):
    """Verify that ExtensionGovernor blocks admission of extensions containing shadow parameters."""
    monkeypatch.setenv("PI_GHOST_STRICT_MODE", "true")

    policy = ExtensionGovernancePolicy()
    ledger = ExtensionProvenanceLedger(ledger_dir=tmp_path / "ledger")
    enforcer = TrustZoneEnforcer()
    governor = ExtensionGovernor(policy=policy, ledger=ledger, trust_enforcer=enforcer)

    from pi_extension_governor.manifest import CapabilityClass

    bundle = ExtensionBundle(
        bundle_id="b_test",
        manifest=ExtensionManifest(
            extension_id="test_ext",
            package_name="test_ext",
            package_version="1.0",
            package_hash="hash_123",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
        ),
        payload_hash="ph_test",
    )

    # Malicious source block containing bypass override assignment
    malicious_source = "def run():\n    bypass = True\n    return 'hacked'\n"

    result = governor.process_bundle(bundle, entrypoint_source=malicious_source, test_inputs={})

    assert not result.admitted
    assert result.status == ExtensionStatus.REJECTED
    assert "shadow parameters detected" in result.reason.lower()


# =====================================================================
# Test 7: Warn-only mode (non-blocking validation when strict is disabled)
# =====================================================================
def test_warn_only_mode(monkeypatch):
    """Verify that when strict is disabled, shadow parameters are registered but don't block."""
    monkeypatch.setenv("PI_GHOST_STRICT_MODE", "false")
    assert not is_strict_mode()

    ghost = PiSchemaGhost()
    scanned_dict, errors = ghost.scan(SAMPLE_SPEC)

    # Should still map the Intent Graph successfully
    assert "x-intent-graph" in scanned_dict
    assert len(scanned_dict["x-intent-graph"]["nodes"]) == 2

    # Should NOT return any policy blocking errors
    assert len(errors) == 0


# =====================================================================
# Test 8: Performance SLA validation (<5ms scan overhead)
# =====================================================================
def test_performance_sla():
    """Verify that SchemaGhost scanning meets low-latency SLAs (<5ms)."""
    # Build a complex dictionary containing 100 endpoints
    large_spec = {"openapi": "3.1.0", "info": {"title": "Large Spec", "version": "1.0"}, "paths": {}}
    for idx in range(100):
        large_spec["paths"][f"/endpoint_{idx}"] = {
            "get": {
                "operationId": f"get_{idx}",
                "parameters": [
                    {"name": f"param_{idx}", "in": "query"},
                    {"name": "admin" if idx % 10 == 0 else "clean", "in": "query"},
                ],
            }
        }

    ghost = PiSchemaGhost()
    start_time = time.perf_counter()
    _, _ = ghost.scan(large_spec)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Large specification scanning should easily complete under 5ms
    assert elapsed_ms < 5.0, f"Performance SLA exceeded: {elapsed_ms:.2f}ms"
