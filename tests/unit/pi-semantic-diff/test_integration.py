"""Cross-runtime integration tests.

Validates that pi-semantic-diff, pi-semantic-radius, and pi-semantic-validator
compose deterministically into a governed pipeline.

No inference. No LLM calls. Deterministic only.
"""

from __future__ import annotations

from pi_semantic_diff.models import (
    AuthInvariant,
    DependencyGraph,
    SemanticField,
    SemanticIRTrace,
    StateEdge,
)
from pi_semantic_diff.runtime import DiffRuntime
from pi_semantic_radius.models import TopologyEdge, TopologyGraph, TopologyNode
from pi_semantic_radius.runtime import RadiusRuntime


def test_pipeline_diff_then_radius() -> None:
    """End-to-end: baseline -> modified -> diff -> radius."""
    # Baseline snapshot
    baseline_traces = [
        SemanticIRTrace(
            endpoint_template="/api/users",
            method="GET",
            fields=[SemanticField(path="id", inferred_type="integer", confidence=0.9, entropy_score=0.1)],
            mutation_class="IDEMPOTENT_READ",
            replay_class="IDEMPOTENT",
        ),
        SemanticIRTrace(
            endpoint_template="/api/users/{id}",
            method="GET",
            fields=[SemanticField(path="name", inferred_type="string", confidence=0.8, entropy_score=0.2)],
            mutation_class="IDEMPOTENT_READ",
            replay_class="IDEMPOTENT",
        ),
    ]
    baseline_graph = DependencyGraph(
        edges=[
            StateEdge(
                upstream_endpoint="/api/users",
                upstream_field="id",
                downstream_endpoint="/api/users/{id}",
                downstream_field="id",
            )
        ],
        nodes=["/api/users", "/api/users/{id}"],
    )
    baseline_auth = [
        AuthInvariant(
            invariant_id="auth1",
            invariant_type="bearer",
            confidence=0.9,
            affected_endpoints=["/api/users", "/api/users/{id}"],
        ),
    ]

    # Modified snapshot: adds destructive endpoint, new dependency, auth drift
    modified_traces = [
        SemanticIRTrace(
            endpoint_template="/api/users",
            method="GET",
            fields=[SemanticField(path="id", inferred_type="integer", confidence=0.9, entropy_score=0.1)],
            mutation_class="IDEMPOTENT_READ",
            replay_class="IDEMPOTENT",
        ),
        SemanticIRTrace(
            endpoint_template="/api/users/{id}",
            method="GET",
            fields=[SemanticField(path="name", inferred_type="string", confidence=0.8, entropy_score=0.2)],
            mutation_class="IDEMPOTENT_READ",
            replay_class="IDEMPOTENT",
        ),
        SemanticIRTrace(
            endpoint_template="/api/users/{id}",
            method="DELETE",
            fields=[],
            mutation_class="DESTRUCTIVE_MUTATION",
            replay_class="NON_REPLAYABLE",
        ),
    ]
    modified_graph = DependencyGraph(
        edges=[
            StateEdge(
                upstream_endpoint="/api/users",
                upstream_field="id",
                downstream_endpoint="/api/users/{id}",
                downstream_field="id",
            ),
            StateEdge(
                upstream_endpoint="/api/users/{id}",
                upstream_field="id",
                downstream_endpoint="/api/audit",
                downstream_field="user_id",
            ),
        ],
        nodes=["/api/users", "/api/users/{id}", "/api/audit"],
    )
    modified_auth = [
        AuthInvariant(
            invariant_id="auth1",
            invariant_type="bearer",
            confidence=0.9,
            affected_endpoints=["/api/users", "/api/users/{id}"],
        ),
        AuthInvariant(
            invariant_id="auth2", invariant_type="otp", confidence=0.7, affected_endpoints=["/api/users/{id}"]
        ),
    ]

    # Run diff
    diff_runtime = DiffRuntime()
    diff_report = diff_runtime.diff(
        baseline_traces=baseline_traces,
        modified_traces=modified_traces,
        baseline_graph=baseline_graph,
        modified_graph=modified_graph,
        baseline_auth=baseline_auth,
        modified_auth=modified_auth,
        baseline_execution_id="recon_v1",
        modified_execution_id="recon_v2",
    )

    # Assertions on diff report
    assert diff_report.drift_score > 0.0
    assert diff_report.state_mutation_expansion >= 1  # DELETE is destructive
    assert diff_report.replay_unsafe_expansion >= 1  # DELETE is non-replayable
    assert diff_report.report_hash != ""

    # Convert dependency graph to topology graph for radius
    def _dep_to_topo(dep_graph: DependencyGraph) -> TopologyGraph:
        nodes = {}
        for n in dep_graph.nodes:
            nodes[n] = TopologyNode(node_id=n)
        edges = []
        for e in dep_graph.edges:
            edges.append(
                TopologyEdge(
                    edge_id=f"{e.upstream_endpoint}->{e.downstream_endpoint}",
                    upstream=e.upstream_endpoint,
                    downstream=e.downstream_endpoint,
                )
            )
        return TopologyGraph(
            graph_id=dep_graph.session_window_id or "graph",
            nodes=nodes,
            edges=edges,
        )

    base_topo = _dep_to_topo(baseline_graph)
    mod_topo = _dep_to_topo(modified_graph)

    # Run radius
    radius_runtime = RadiusRuntime()
    risk_report = radius_runtime.run(base_topo, mod_topo)

    # Assertions on risk report
    assert risk_report.report_id.startswith("radius_")
    assert risk_report.max_topology_depth_delta >= 1  # depth increased from 1 to 2
    assert risk_report.report_hash != ""

    # Cross-runtime invariant: diff drift score and radius dependency expansion
    # must be monotonically related (more drift -> more expansion)
    if diff_report.drift_score > 0.3:
        assert risk_report.total_dependency_expansion >= 1


def test_pipeline_no_change_clean_pass() -> None:
    """Identical baseline and modified should produce zero drift, zero risk."""
    traces = [
        SemanticIRTrace(
            endpoint_template="/api/users",
            method="GET",
            fields=[SemanticField(path="id", inferred_type="integer", confidence=0.9, entropy_score=0.1)],
            mutation_class="IDEMPOTENT_READ",
            replay_class="IDEMPOTENT",
        ),
    ]
    graph = DependencyGraph(edges=[], nodes=["/api/users"])
    auth = [AuthInvariant(invariant_id="auth1", invariant_type="bearer", confidence=0.9)]

    diff_runtime = DiffRuntime()
    diff_report = diff_runtime.diff(traces, traces, graph, graph, auth, auth)

    assert diff_report.drift_score == 0.0
    assert diff_report.structural_delta_score == 0.0
    assert diff_report.semantic_delta_score == 0.0

    topo = TopologyGraph(
        graph_id="g1",
        nodes={"/api/users": TopologyNode(node_id="/api/users")},
        edges=[],
    )
    radius_runtime = RadiusRuntime()
    risk_report = radius_runtime.run(topo, topo)

    assert risk_report.total_dependency_expansion == 0
    assert risk_report.limits_exceeded == []


class TestDiffReportReproducibility:
    """Regression tests for the deterministic-kernel reproducibility claim.

    The report hash must be a pure function of the LOGICAL diff content. It must
    NOT vary across runs because of wall-clock time (generated_at) or the random
    per-run report_id (uuid4-derived). Set-difference iteration that feeds delta
    ordering must also be deterministic.
    """

    @staticmethod
    def _build_inputs():
        baseline_traces = [
            SemanticIRTrace(
                endpoint_template="/api/users",
                method="GET",
                fields=[SemanticField(path="id", inferred_type="integer", confidence=0.9, entropy_score=0.1)],
                mutation_class="IDEMPOTENT_READ",
                replay_class="IDEMPOTENT",
            ),
        ]
        modified_traces = [
            SemanticIRTrace(
                endpoint_template="/api/users",
                method="GET",
                fields=[SemanticField(path="id", inferred_type="string", confidence=0.9, entropy_score=0.1)],
                mutation_class="IDEMPOTENT_READ",
                replay_class="IDEMPOTENT",
            ),
            SemanticIRTrace(
                endpoint_template="/api/users/{id}",
                method="DELETE",
                mutation_class="DESTRUCTIVE_MUTATION",
                replay_class="NON_REPLAYABLE",
            ),
        ]
        # Node sets whose unsorted difference iteration previously varied per run.
        baseline_graph = DependencyGraph(nodes=["n1", "n2", "n3", "n4", "n5"])
        modified_graph = DependencyGraph(nodes=["x1", "x2", "x3", "x4", "x5"])
        return baseline_traces, modified_traces, baseline_graph, modified_graph

    def _run(self):
        bt, mt, bg, mg = self._build_inputs()
        # Two FRESH runtime instances (each mints its own random report_id).
        return DiffRuntime().diff(
            baseline_traces=bt,
            modified_traces=mt,
            baseline_graph=bg,
            modified_graph=mg,
            baseline_execution_id="recon_v1",
            modified_execution_id="recon_v2",
        )

    def test_report_hash_is_reproducible(self) -> None:
        """Same logical input -> identical report_hash across fresh instances."""
        report_a = self._run()
        report_b = self._run()

        assert report_a.report_hash != ""
        assert report_a.report_hash == report_b.report_hash

    def test_node_delta_ordering_is_deterministic(self) -> None:
        """Set-difference iteration feeding the hash must be sorted/stable."""
        report_a = self._run()
        report_b = self._run()

        added_a = [d.node for d in report_a.dependency_deltas if d.delta_type == "NODE_ADDED"]
        added_b = [d.node for d in report_b.dependency_deltas if d.delta_type == "NODE_ADDED"]
        removed_a = [d.node for d in report_a.dependency_deltas if d.delta_type == "NODE_REMOVED"]

        assert added_a == added_b
        assert added_a == sorted(added_a)
        assert removed_a == sorted(removed_a)

    def test_report_id_is_still_recorded_and_unique(self) -> None:
        """report_id is retained as metadata (unique) but excluded from the hash."""
        report_a = self._run()
        report_b = self._run()

        # Still present and shaped as before.
        assert report_a.report_id.startswith("diff_")
        assert report_b.report_id.startswith("diff_")
        # Distinct per run (uuid4-derived metadata) yet the hash matches.
        assert report_a.report_id != report_b.report_id
        assert report_a.report_hash == report_b.report_hash

    def test_generated_at_timestamp_is_still_recorded(self) -> None:
        """The wall-clock timestamp is still stored, just not in the hash."""
        report = self._run()
        assert report.generated_at is not None
        assert report.generated_at.tzinfo is not None
        # Two reports built at different wall-clock instants share one hash.
        assert self._run().report_hash == report.report_hash

    def test_empty_report_hash_is_reproducible(self) -> None:
        """The fail-closed empty-report path is also content-addressed."""
        report_a = DiffRuntime().diff([], [], baseline_execution_id="b", modified_execution_id="m")
        report_b = DiffRuntime().diff([], [], baseline_execution_id="b", modified_execution_id="m")

        assert report_a.report_hash == report_b.report_hash
        assert report_a.report_id != report_b.report_id
        assert report_a.generated_at is not None
