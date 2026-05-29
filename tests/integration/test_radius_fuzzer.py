"""Integration tests for the Radius-Fuzzer Engine."""

from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

from pi_agent_interceptor.proxy import app, ledger, DATABASE_PATH
from pi_semantic_radius import (
    RadiusFuzzerEngine,
    FuzzTarget,
    SemanticParameterSpec,
    MutationPayload,
)


@pytest.fixture(autouse=True)
def cleanup_test_db():
    """Ensures a clean database before and after each test run."""
    # Delete the test DB file if it exists
    if os.path.exists(DATABASE_PATH):
        try:
            os.remove(DATABASE_PATH)
        except OSError:
            pass
        
    # Re-initialize ledger
    ledger._initialize_db()
    
    yield
    
    # Final cleanup
    if os.path.exists(DATABASE_PATH):
        try:
            os.remove(DATABASE_PATH)
        except OSError:
            pass



def test_fuzzer_target_ranking():
    """Verify that targets are ranked correctly based on Blast Radius and parameters count."""
    engine = RadiusFuzzerEngine()

    targets = [
        FuzzTarget(
            path="/v1/users",
            method="get",
            parameters=[SemanticParameterSpec(name="id", type_str="uuid")],
            blast_radius=3
        ),
        FuzzTarget(
            path="/v1/payments",
            method="post",
            parameters=[
                SemanticParameterSpec(name="amount", type_str="int"),
                SemanticParameterSpec(name="currency", type_str="string")
            ],
            blast_radius=85
        )
    ]

    ranked = engine.prioritize_targets(targets)
    assert len(ranked) == 2
    assert ranked[0].path == "/v1/payments"  # Highest blast radius and param complexity
    assert ranked[0].sd_score > ranked[1].sd_score


def test_fuzzer_type_confusion_generation():
    """Verify that type-confusion mutations produce correctly structured dynamic types."""
    engine = RadiusFuzzerEngine()

    uuid_param = SemanticParameterSpec(name="user_id", type_str="uuid")
    int_param = SemanticParameterSpec(name="count", type_str="int")
    float_param = SemanticParameterSpec(name="rate", type_str="float")

    uuid_confusion = engine.generate_type_confusion(uuid_param)
    assert isinstance(uuid_confusion, list)  # Dynamic array confusion
    assert len(uuid_confusion) == 2

    int_confusion = engine.generate_type_confusion(int_param)
    assert isinstance(int_confusion, str)
    assert int_confusion == "not_an_integer_string"

    float_confusion = engine.generate_type_confusion(float_param)
    assert isinstance(float_confusion, dict)
    assert "scientific_notation" in float_confusion


def test_fuzzer_boundary_overflow_generation():
    """Verify boundary overflow inputs are extreme limits."""
    engine = RadiusFuzzerEngine()

    int_param = SemanticParameterSpec(name="limit", type_str="int")
    str_param = SemanticParameterSpec(name="name", type_str="string")

    int_overflow = engine.generate_boundary_overflow(int_param)
    assert isinstance(int_overflow, int)
    assert int_overflow > 10**30  # Numerical big int boundary

    str_overflow = engine.generate_boundary_overflow(str_param)
    assert len(str_overflow) == 50000


def test_shadow_parameter_enumeration():
    """Verify shadow parameter enumeration generates payloads containing estimated params."""
    engine = RadiusFuzzerEngine()

    target = FuzzTarget(
        path="/v1/login",
        method="post",
        parameters=[SemanticParameterSpec(name="username", type_str="string")]
    )

    payloads = engine.enumerate_undocumented_parameters(target)
    assert len(payloads) == len(engine.SHADOW_PARAMETERS)

    # Check that a shadow parameter (e.g. 'admin') was injected
    has_admin = False
    for p in payloads:
        if "admin" in p.params:
            has_admin = True
            assert p.params["admin"] is True
    assert has_admin


def test_interceptor_chat_completions_happy_path():
    """Verify that a happy-path LLM proxy chat request works through the proxy."""
    client = TestClient(app)

    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a safe assistant."},
            {"role": "user", "content": "Hello! How do I format a date?"}
        ],
        "temperature": 0.5
    }

    # Since the real backend LLM requires authorization, the proxy should return a 502
    # or 401 when it tries to call the target url without a valid token.
    # We verify it passes all initial safety gates (no 403 drift halt).
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code in [502, 200, 401]

