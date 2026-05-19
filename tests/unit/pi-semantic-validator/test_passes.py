"""Test suite for all deterministic validation passes."""

from __future__ import annotations

import pytest

from pi_semantic_validator.models import (
    AuthInvariant,
    DependencyGraph,
    SemanticDiff,
    SemanticIRTrace,
    StateEdge,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerStatus,
)
from pi_semantic_validator.policy import (
    ArchitecturePolicy,
    BlastRadiusLimit,
    ForbiddenImportRule,
    LayerDefinition,
    LayerRule,
    MutationRule,
    ReplayRule,
    StateWriterRule,
    TrustBoundaryRule,
    TrustZone,
)
from pi_semantic_validator.passes.boundary import BoundaryValidationPass
from pi_semantic_validator.passes.layer import LayerValidationPass
from pi_semantic_validator.passes.mutation_drift import MutationDriftValidationPass
from pi_semantic_validator.passes.replay_safety import ReplaySafetyValidationPass
from pi_semantic_validator.passes.blast_radius import BlastRadiusValidationPass


def _make_envelope(artifacts, policy):
    return {
        "execution_id": "exec_test_001",
        "artifacts": artifacts,
        "policy": policy,
        "bounds": ValidationBoundsConfig(),
    }


# ──────────────────────────────
#  Boundary Pass Tests
# ──────────────────────────────

def test_boundary_pass_no_violations():
    policy = ArchitecturePolicy(
        policy_id="test",
        trust_zones=[TrustZone(zone_id="internal", endpoint_patterns=["/api/*"])],
    )
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/api/a", "/api/b"],
        edges=[StateEdge(upstream_endpoint="/api/a", upstream_field="id", downstream_endpoint="/api/b", downstream_field="user_id")],
    )
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BoundaryValidationPass().execute(envelope)
    assert result.status == WorkerStatus.SUCCESS
    assert not result.violations


def test_boundary_pass_forbidden_crossing():
    policy = ArchitecturePolicy(
        policy_id="test",
        trust_zones=[
            TrustZone(zone_id="public", endpoint_patterns=["/public/*"]),
            TrustZone(zone_id="internal", endpoint_patterns=["/api/*"]),
        ],
        trust_boundary_rules=[
            TrustBoundaryRule(rule_id="no-pub-to-int", from_zone="public", to_zone="internal", action="FORBIDDEN")
        ],
    )
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/public/login", "/api/users"],
        edges=[StateEdge(upstream_endpoint="/public/login", upstream_field="token", downstream_endpoint="/api/users", downstream_field="auth")],
    )
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BoundaryValidationPass().execute(envelope)
    assert any(v.rule == "FORBIDDEN_TRUST_BOUNDARY_CROSSING" for v in result.violations)


def test_boundary_pass_unauthorized_state_writer():
    policy = ArchitecturePolicy(
        policy_id="test",
        global_fail_closed=True,
        layers=[LayerDefinition(layer_id="frontend", endpoint_patterns=["/public/*"])],
        state_writer_rules=[],
    )
    trace = SemanticIRTrace(endpoint_template="/public/login", method="POST", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash2",
    )
    envelope = _make_envelope([art], policy)
    result = BoundaryValidationPass().execute(envelope)
    assert any(v.rule == "UNAUTHORIZED_STATE_WRITER" for v in result.violations)


# ──────────────────────────────
#  Layer Pass Tests
# ──────────────────────────────

def test_layer_pass_forbidden_import():
    policy = ArchitecturePolicy(
        policy_id="test",
        layers=[
            LayerDefinition(layer_id="frontend", endpoint_patterns=["/public/*"], forbidden_importers=["backend"]),
            LayerDefinition(layer_id="backend", endpoint_patterns=["/api/*"]),
        ],
        layer_rules=[
            LayerRule(rule_id="front-no-back", from_layer="frontend", to_layer="backend", action="FORBIDDEN")
        ],
    )
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/public/login", "/api/users"],
        edges=[StateEdge(upstream_endpoint="/public/login", upstream_field="x", downstream_endpoint="/api/users", downstream_field="y")],
    )
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = LayerValidationPass().execute(envelope)
    assert any(v.rule == "FORBIDDEN_LAYER_IMPORT" for v in result.violations)


def test_layer_pass_inversion_detected():
    policy = ArchitecturePolicy(
        policy_id="test",
        layers=[
            LayerDefinition(layer_id="frontend", endpoint_patterns=["/public/*"], forbidden_importers=["backend"]),
            LayerDefinition(layer_id="backend", endpoint_patterns=["/api/*"]),
        ],
    )
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/api/users", "/public/login"],
        edges=[StateEdge(upstream_endpoint="/api/users", upstream_field="x", downstream_endpoint="/public/login", downstream_field="y")],
    )
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = LayerValidationPass().execute(envelope)
    assert any(v.rule == "BACKEND_FRONTEND_INVERSION_DETECTED" for v in result.violations)


# ──────────────────────────────
#  Mutation Drift Pass Tests
# ──────────────────────────────

def test_mutation_drift_class_violation():
    policy = ArchitecturePolicy(
        policy_id="test",
        mutation_rules=[
            MutationRule(
                rule_id="api-post",
                endpoint_pattern="/api/*",
                methods=["GET", "POST"],
                allowed_mutation_classes=["STATEFUL_MUTATION"],
                requires_auth_for_mutation=True,
            )
        ],
        blast_radius_limits=BlastRadiusLimit(),
    )
    trace = SemanticIRTrace(endpoint_template="/api/users", method="GET", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = MutationDriftValidationPass().execute(envelope)
    # GET is IDEMPOTENT_READ, which is not in allowed list [STATEFUL_MUTATION]
    assert any(v.rule == "MUTATION_CLASS_POLICY_VIOLATION" for v in result.violations)


def test_mutation_drift_missing_auth():
    policy = ArchitecturePolicy(
        policy_id="test",
        mutation_rules=[
            MutationRule(
                rule_id="api-post",
                endpoint_pattern="/api/*",
                methods=["POST"],
                allowed_mutation_classes=["STATEFUL_MUTATION"],
                requires_auth_for_mutation=True,
            )
        ],
        blast_radius_limits=BlastRadiusLimit(),
    )
    trace = SemanticIRTrace(endpoint_template="/api/users", method="POST", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = MutationDriftValidationPass().execute(envelope)
    assert any(v.rule == "STATEFUL_MUTATION_MISSING_AUTH_INVARIANT" for v in result.violations)


def test_mutation_drift_delta_limit():
    policy = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_structural_delta_score=0.1),
    )
    diff = SemanticDiff(structural_delta_score=0.5, semantic_delta_score=0.0)
    art = ValidationArtifact(
        artifact_id="d1",
        artifact_type="SemanticDiff",
        payload=diff.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = MutationDriftValidationPass().execute(envelope)
    assert any(v.rule == "STRUCTURAL_DELTA_EXCEEDS_LIMIT" for v in result.violations)


# ──────────────────────────────
#  Replay Safety Pass Tests
# ──────────────────────────────

def test_replay_safety_production_prohibited():
    policy = ArchitecturePolicy(
        policy_id="test",
        replay_rules=[
            ReplayRule(
                rule_id="admin-post",
                endpoint_pattern="/admin/*",
                methods=["POST"],
                required_replay_class="NON_REPLAYABLE",
                production_replay_prohibited=True,
            )
        ],
        blast_radius_limits=BlastRadiusLimit(),
    )
    trace = SemanticIRTrace(endpoint_template="/admin/delete", method="POST", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = ReplaySafetyValidationPass().execute(envelope)
    assert any(v.rule == "PRODUCTION_REPLAY_PROHIBITED" for v in result.violations)


def test_replay_safety_sandbox_required():
    policy = ArchitecturePolicy(
        policy_id="test",
        replay_rules=[
            ReplayRule(
                rule_id="admin-post",
                endpoint_pattern="/admin/*",
                methods=["POST"],
                required_replay_class="NON_REPLAYABLE",
                sandbox_required=True,
                sandbox_replayable_mutations=["IDEMPOTENT_READ"],
            )
        ],
        blast_radius_limits=BlastRadiusLimit(),
    )
    trace = SemanticIRTrace(endpoint_template="/admin/delete", method="POST", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = ReplaySafetyValidationPass().execute(envelope)
    assert any(v.rule == "SANBOX_REQUIRED_ROUTE_NOT_SANDBOX_REPLAYABLE" for v in result.violations)


def test_replay_safety_class_mismatch():
    policy = ArchitecturePolicy(
        policy_id="test",
        replay_rules=[
            ReplayRule(
                rule_id="api-get",
                endpoint_pattern="/api/*",
                methods=["GET"],
                required_replay_class="PURE_REPLAYABLE",
                production_replay_prohibited=False,
            )
        ],
        blast_radius_limits=BlastRadiusLimit(),
    )
    trace = SemanticIRTrace(endpoint_template="/api/users", method="GET", fields=[])
    art = ValidationArtifact(
        artifact_id="t1",
        artifact_type="SemanticIRTrace",
        payload=trace.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = ReplaySafetyValidationPass().execute(envelope)
    # GET -> IDEMPOTENT_READ -> PURE_REPLAYABLE, which matches required_replay_class
    assert not any(v.rule == "REPLAY_CLASSIFICATION_MISMATCH" for v in result.violations)


# ──────────────────────────────
#  Blast Radius Pass Tests
# ──────────────────────────────

def test_blast_radius_dependency_limit():
    policy = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_dependencies_per_endpoint=2),
    )
    edges = [
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/b", downstream_field="y"),
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/c", downstream_field="y"),
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/d", downstream_field="y"),
    ]
    graph = DependencyGraph(session_window_id="sw1", nodes=["/api/a", "/api/b", "/api/c", "/api/d"], edges=edges)
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BlastRadiusValidationPass().execute(envelope)
    assert any(v.rule == "DEPENDENCY_EXPANSION_LIMIT_EXCEEDED" for v in result.violations)


def test_blast_radius_fanout_limit():
    policy = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_fanout_per_endpoint=1),
    )
    edges = [
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/b", downstream_field="y"),
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/c", downstream_field="y"),
    ]
    graph = DependencyGraph(session_window_id="sw1", nodes=["/api/a", "/api/b", "/api/c"], edges=edges)
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BlastRadiusValidationPass().execute(envelope)
    assert any(v.rule == "FANOUT_LIMIT_EXCEEDED" for v in result.violations)


def test_blast_radius_topology_complexity():
    policy = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_topology_complexity_score=1.0),
    )
    edges = [
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/b", downstream_field="y"),
        StateEdge(upstream_endpoint="/api/a", upstream_field="x", downstream_endpoint="/api/c", downstream_field="y"),
        StateEdge(upstream_endpoint="/api/b", upstream_field="x", downstream_endpoint="/api/c", downstream_field="y"),
    ]
    graph = DependencyGraph(session_window_id="sw1", nodes=["/api/a", "/api/b", "/api/c"], edges=edges)
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BlastRadiusValidationPass().execute(envelope)
    # 3 edges / 3 nodes = 1.0 complexity; at limit, no violation
    # Let's set lower
    policy2 = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_topology_complexity_score=0.5),
    )
    envelope2 = _make_envelope([art], policy2)
    result2 = BlastRadiusValidationPass().execute(envelope2)
    assert any(v.rule == "TOPOLOGY_COMPLEXITY_GROWTH_EXCEEDED" for v in result2.violations)


def test_blast_radius_replay_scope():
    policy = ArchitecturePolicy(
        policy_id="test",
        blast_radius_limits=BlastRadiusLimit(max_replay_scope_nodes=2),
    )
    graph = DependencyGraph(session_window_id="sw1", nodes=["/api/a", "/api/b", "/api/c"], edges=[])
    art = ValidationArtifact(
        artifact_id="g1",
        artifact_type="DependencyGraph",
        payload=graph.model_dump(),
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BlastRadiusValidationPass().execute(envelope)
    assert any(v.rule == "REPLAY_SCOPE_NODE_COUNT_EXCEEDED" for v in result.violations)


# ──────────────────────────────
#  Unparseable Artifact Tests (fail-closed)
# ──────────────────────────────

def test_unparseable_graph_boundary():
    policy = ArchitecturePolicy(policy_id="test")
    art = ValidationArtifact(
        artifact_id="bad",
        artifact_type="DependencyGraph",
        payload={"invalid": "data"},
        semantic_hash="hash1",
    )
    envelope = _make_envelope([art], policy)
    result = BoundaryValidationPass().execute(envelope)
    assert any(v.rule == "UNPARSEABLE_DEPENDENCY_GRAPH" for v in result.violations)


def test_empty_artifacts_runtime_indeterminate():
    from pi_semantic_validator.runtime import ValidatorRuntime
    policy = ArchitecturePolicy(policy_id="test", global_fail_closed=True)
    runtime = ValidatorRuntime(policy=policy)
    report = runtime.run([])
    assert report.status == "FAIL"
    assert any(v.rule == "NO_ARTIFACTS_PROVIDED" for v in report.violations)
