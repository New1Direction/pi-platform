"""Tests for pi-semantic-diff delta computations."""

from __future__ import annotations

from pi_semantic_diff.models import (
    SemanticIRTrace,
    SemanticField,
    DependencyGraph,
    StateEdge,
    AuthInvariant,
)
from pi_semantic_diff.deltas import (
    compute_endpoint_deltas,
    compute_dependency_deltas,
    compute_auth_deltas,
    compute_replay_surface_deltas,
    compute_structural_delta_score,
    compute_semantic_delta_score,
    compute_drift_score,
)


def test_endpoint_added() -> None:
    baseline = []
    modified = [SemanticIRTrace(endpoint_template="/api/users", method="GET")]
    deltas = compute_endpoint_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].presence == "ADDED"
    assert deltas[0].endpoint_template == "/api/users"


def test_endpoint_removed() -> None:
    baseline = [SemanticIRTrace(endpoint_template="/api/users", method="GET")]
    modified = []
    deltas = compute_endpoint_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].presence == "REMOVED"


def test_field_type_change_detected() -> None:
    baseline = [
        SemanticIRTrace(
            endpoint_template="/api/users",
            method="GET",
            fields=[SemanticField(path="id", inferred_type="integer", confidence=0.9, entropy_score=0.1)],
        )
    ]
    modified = [
        SemanticIRTrace(
            endpoint_template="/api/users",
            method="GET",
            fields=[SemanticField(path="id", inferred_type="string", confidence=0.9, entropy_score=0.1)],
        )
    ]
    deltas = compute_endpoint_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].presence == "UNCHANGED"
    assert len(deltas[0].field_deltas) == 1
    assert deltas[0].field_deltas[0].delta_type == "TYPE_CHANGED"
    assert deltas[0].field_deltas[0].severity == "CRITICAL"


def test_mutation_class_transition_detected() -> None:
    baseline = [SemanticIRTrace(endpoint_template="/api/users", method="GET", mutation_class="IDEMPOTENT_READ")]
    modified = [SemanticIRTrace(endpoint_template="/api/users", method="GET", mutation_class="STATEFUL_MUTATION")]
    deltas = compute_endpoint_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].mutation_class_transition is True


def test_dependency_edge_added() -> None:
    baseline = DependencyGraph(edges=[], nodes=["n1"])
    modified = DependencyGraph(
        edges=[StateEdge(upstream_endpoint="n1", upstream_field="id", downstream_endpoint="n2", downstream_field="user_id")],
        nodes=["n1", "n2"],
    )
    deltas = compute_dependency_deltas(baseline, modified)
    assert len(deltas) == 2  # edge added + node added
    assert any(d.delta_type == "EDGE_ADDED" for d in deltas)


def test_auth_invariant_removed() -> None:
    baseline = [AuthInvariant(invariant_id="auth1", invariant_type="bearer", confidence=0.9)]
    modified = []
    deltas = compute_auth_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].delta_type == "REMOVED"


def test_replay_surface_new_unsafe_endpoint() -> None:
    baseline = []
    modified = [SemanticIRTrace(endpoint_template="/api/pay", method="POST", replay_class="NON_REPLAYABLE")]
    deltas = compute_replay_surface_deltas(baseline, modified)
    assert len(deltas) == 1
    assert deltas[0].replayable_delta is True


def test_structural_score_bounded() -> None:
    ep_deltas = [
        SemanticIRTrace(endpoint_template="/a", method="GET").model_copy(update={"presence": "ADDED"})
    ]
    # Can't pass SemanticIRTrace to structural score; it expects EndpointDelta
    from pi_semantic_diff.models import EndpointDelta
    endpoint_deltas = [EndpointDelta(endpoint_template="/a", method="GET", presence="ADDED")]
    dep_deltas = []
    score = compute_structural_delta_score(endpoint_deltas, dep_deltas)
    assert 0.0 <= score <= 1.0


def test_drift_score_computation() -> None:
    score = compute_drift_score(structural=0.2, semantic=0.3, mutation_exp=2, replay_exp=1)
    assert 0.0 <= score <= 1.0
