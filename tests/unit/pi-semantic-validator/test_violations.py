"""Test suite for violation builder determinism and evidence binding."""

from __future__ import annotations

from pi_semantic_validator.violations import ViolationBuilder


def test_violation_builder_critical():
    vb = ViolationBuilder("boundary")
    v = vb.critical(
        rule="FORBIDDEN_TRUST_BOUNDARY_CROSSING",
        endpoint="/public/login -> /api/users",
        field_path="token",
        provenance=["graph:sw1", "edge:0"],
        replay_evidence=["replay:exec_001"],
        file_evidence="src/auth.py",
        module_evidence="auth_module",
        extra={"zone_a": "public", "zone_b": "internal"},
    )
    assert v.severity == "CRITICAL"
    assert v.rule == "FORBIDDEN_TRUST_BOUNDARY_CROSSING"
    assert v.pass_name == "boundary"
    assert v.action_taken == "HALT"
    assert v.context["endpoint"] == "/public/login -> /api/users"
    assert v.context["field_path"] == "token"
    assert v.context["provenance_chain"] == ["graph:sw1", "edge:0"]
    assert v.context["replay_evidence"] == ["replay:exec_001"]
    assert v.context["file_evidence"] == "src/auth.py"
    assert v.context["module_evidence"] == "auth_module"
    assert v.context["zone_a"] == "public"
    assert v.violation_id.startswith("viol_")


def test_violation_builder_error():
    vb = ViolationBuilder("mutation_drift")
    v = vb.error(
        rule="MUTATION_CLASS_POLICY_VIOLATION",
        endpoint="/api/users",
        provenance=["trace:0"],
    )
    assert v.severity == "ERROR"
    assert v.action_taken == "HALT"


def test_violation_builder_warning():
    vb = ViolationBuilder("layer")
    v = vb.warning(
        rule="FORBIDDEN_IMPORT_RULE_UNVERIFIABLE_NO_SOURCE_ARTIFACTS",
    )
    assert v.severity == "WARNING"
    assert v.action_taken == "LOG"


def test_violation_ids_unique():
    vb = ViolationBuilder("test")
    v1 = vb.error(rule="R1")
    v2 = vb.error(rule="R2")
    assert v1.violation_id != v2.violation_id
