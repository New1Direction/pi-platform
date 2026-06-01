"""Test suite for validator runtime integration."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pi_semantic_validator.models import (
    DependencyGraph,
    SemanticIRTrace,
    StateEdge,
    ValidationArtifact,
    ValidationBoundsConfig,
)
from pi_semantic_validator.policy import (
    ArchitecturePolicy,
    LayerDefinition,
    TrustBoundaryRule,
    TrustZone,
)
from pi_semantic_validator.runtime import ValidatorRuntime, run_validator


def _build_policy() -> ArchitecturePolicy:
    return ArchitecturePolicy(
        policy_id="integration-test",
        trust_zones=[
            TrustZone(zone_id="public", endpoint_patterns=["/public/*"]),
            TrustZone(zone_id="internal", endpoint_patterns=["/api/*"]),
        ],
        trust_boundary_rules=[
            TrustBoundaryRule(
                rule_id="no-pub-to-int",
                from_zone="public",
                to_zone="internal",
                action="FORBIDDEN",
            )
        ],
        global_fail_closed=True,
    )


def _build_artifacts() -> list[ValidationArtifact]:
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/public/login", "/api/users"],
        edges=[
            StateEdge(
                upstream_endpoint="/public/login",
                upstream_field="token",
                downstream_endpoint="/api/users",
                downstream_field="auth",
            )
        ],
    )
    trace = SemanticIRTrace(endpoint_template="/api/users", method="GET", fields=[])
    return [
        ValidationArtifact(
            artifact_id="g1",
            artifact_type="DependencyGraph",
            payload=graph.model_dump(),
            semantic_hash="hash_graph",
        ),
        ValidationArtifact(
            artifact_id="t1",
            artifact_type="SemanticIRTrace",
            payload=trace.model_dump(),
            semantic_hash="hash_trace",
        ),
    ]


def test_runtime_fail_with_critical_violation():
    policy = _build_policy()
    artifacts = _build_artifacts()
    runtime = ValidatorRuntime(policy=policy)
    report = runtime.run(artifacts)
    assert report.status == "FAIL"
    assert any(v.rule == "FORBIDDEN_TRUST_BOUNDARY_CROSSING" for v in report.violations)
    assert report.has_critical is True
    assert report.has_errors is True
    assert report.summary["passes_executed"] == 5


def test_runtime_pass_clean():
    policy = ArchitecturePolicy(
        policy_id="clean",
        trust_zones=[TrustZone(zone_id="internal", endpoint_patterns=["/api/*"])],
        layers=[LayerDefinition(layer_id="backend", endpoint_patterns=["/api/*"])],
        global_fail_closed=False,
    )
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/api/a", "/api/b"],
        edges=[
            StateEdge(
                upstream_endpoint="/api/a",
                upstream_field="id",
                downstream_endpoint="/api/b",
                downstream_field="user_id",
            )
        ],
    )
    trace = SemanticIRTrace(endpoint_template="/api/a", method="GET", fields=[])
    artifacts = [
        ValidationArtifact(
            artifact_id="g1",
            artifact_type="DependencyGraph",
            payload=graph.model_dump(),
            semantic_hash="hash_graph",
        ),
        ValidationArtifact(
            artifact_id="t1",
            artifact_type="SemanticIRTrace",
            payload=trace.model_dump(),
            semantic_hash="hash_trace",
        ),
    ]
    runtime = ValidatorRuntime(policy=policy)
    report = runtime.run(artifacts)
    assert report.status == "PASS"
    assert not report.has_errors
    assert report.summary["total_violations"] == 0


def test_runtime_bounded_violation_truncation():
    policy = _build_policy()
    # Create many edges to trigger many violations
    edges = [
        StateEdge(
            upstream_endpoint="/public/login",
            upstream_field="token",
            downstream_endpoint="/api/users",
            downstream_field="auth",
        )
        for _ in range(200)
    ]
    graph = DependencyGraph(
        session_window_id="sw1",
        nodes=["/public/login", "/api/users"],
        edges=edges,
    )
    artifacts = [
        ValidationArtifact(
            artifact_id="g1",
            artifact_type="DependencyGraph",
            payload=graph.model_dump(),
            semantic_hash="hash_graph",
        ),
    ]
    bounds = ValidationBoundsConfig(max_violations_per_pass=10)
    runtime = ValidatorRuntime(policy=policy, bounds=bounds)
    report = runtime.run(artifacts)
    # Should contain the bounded truncation violation
    assert any(v.rule == "BOUNDED_EXECUTION_VIOLATION_LIMIT_EXCEEDED" for v in report.violations)


def test_run_validator_from_files():
    policy = _build_policy()
    artifacts = _build_artifacts()

    with tempfile.TemporaryDirectory() as td:
        policy_path = Path(td) / "policy.json"
        with open(policy_path, "w") as f:
            json.dump(policy.model_dump(), f)

        art_path = Path(td) / "artifacts.json"
        with open(art_path, "w") as f:
            json.dump([a.model_dump() for a in artifacts], f)

        report = run_validator(policy_path=policy_path, artifact_paths=[art_path])
        assert report.status == "FAIL"
        assert report.policy_hash == policy.compute_hash()


def test_report_hashes_stable():
    policy = _build_policy()
    artifacts = _build_artifacts()
    runtime = ValidatorRuntime(policy=policy)
    report1 = runtime.run(artifacts)
    report2 = runtime.run(artifacts)
    assert report1.policy_hash == report2.policy_hash
    assert report1.artifacts_hash == report2.artifacts_hash


class TestReportReproducibility:
    """Regression: a validation report's reproducibility proof must be a pure
    function of the LOGICAL input.

    The same logical (policy, artifacts) reproduces an IDENTICAL
    ``policy_hash``, ``artifacts_hash`` and content-addressed ``report_id``
    across two FRESH runtime + policy instances. Wall-clock provenance
    (``generated_at``) and the random per-run ``execution_id`` are kept as
    stored metadata but excluded from the reproducibility proof.
    """

    def test_report_hashes_are_reproducible(self):
        import time

        # Fresh policy + fresh runtime instances on each run, with a
        # wall-clock gap so any contamination would surface.
        report1 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())
        time.sleep(0.01)
        report2 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())

        assert report1.policy_hash == report2.policy_hash
        assert report1.artifacts_hash == report2.artifacts_hash

    def test_report_id_hash_is_reproducible(self):
        import time

        report1 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())
        time.sleep(0.01)
        report2 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())

        # report_id is content-addressed (derived from the reproducible hashes
        # + status + sorted violation rules), not a random uuid.
        assert report1.report_id == report2.report_id
        assert report1.report_id.startswith("report_")

    def test_report_timestamp_and_execution_id_still_recorded(self):
        report = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())
        # Timestamp metadata is still recorded on the report.
        assert report.generated_at is not None
        # A unique runtime execution id is still recorded as metadata.
        assert report.execution_id
        assert report.execution_id.startswith("val_")

    def test_reusing_one_runtime_does_not_accumulate_state(self):
        # Finding: run() appended to self._violations (init'd only in __init__)
        # with no reset, so calling run() twice on ONE instance doubled the
        # violations and changed the content-addressed report_id. Reusing an
        # instance must be reproducible, like a fresh one.
        runtime = ValidatorRuntime(policy=_build_policy())
        r1 = runtime.run([])  # NO_ARTIFACTS_PROVIDED -> 1 violation
        r2 = runtime.run([])  # must NOT accumulate to 2
        assert r1.summary["total_violations"] == r2.summary["total_violations"]
        assert r1.report_id == r2.report_id

    def test_report_execution_id_is_unique_per_run(self):
        # The runtime execution id remains a unique per-run handle (metadata),
        # independent of the content-addressed reproducibility proof.
        report1 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())
        report2 = ValidatorRuntime(policy=_build_policy()).run(_build_artifacts())
        assert report1.execution_id != report2.execution_id
