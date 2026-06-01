"""Tests for pi-semantic-radius engine and runtime."""

from __future__ import annotations

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import TopologyEdge, TopologyGraph, TopologyNode
from pi_semantic_radius.passes.auth_boundary import AuthBoundaryPass
from pi_semantic_radius.passes.mutation_impact import MutationImpactPass
from pi_semantic_radius.passes.propagation_risk import PropagationRiskPass
from pi_semantic_radius.passes.replay_hazard import ReplayHazardPass
from pi_semantic_radius.passes.topology_expansion import TopologyExpansionPass
from pi_semantic_radius.runtime import RadiusRuntime


def test_topology_graph_fanout() -> None:
    graph = TopologyGraph(
        graph_id="g1",
        nodes={
            "n1": TopologyNode(node_id="n1"),
            "n2": TopologyNode(node_id="n2"),
            "n3": TopologyNode(node_id="n3"),
        },
        edges=[
            TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
            TopologyEdge(edge_id="e2", upstream="n1", downstream="n3"),
        ],
    )
    assert graph.fanout("n1") == 2
    assert graph.fanout("n2") == 0


def test_topology_graph_depth() -> None:
    graph = TopologyGraph(
        graph_id="g1",
        nodes={
            "n1": TopologyNode(node_id="n1"),
            "n2": TopologyNode(node_id="n2"),
            "n3": TopologyNode(node_id="n3"),
        },
        edges=[
            TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
            TopologyEdge(edge_id="e2", upstream="n2", downstream="n3"),
        ],
    )
    assert graph.depth_from("n1") == 2
    assert graph.depth_from("n2") == 1
    assert graph.depth_from("n3") == 0


def test_topology_graph_reachable() -> None:
    graph = TopologyGraph(
        graph_id="g1",
        nodes={
            "n1": TopologyNode(node_id="n1"),
            "n2": TopologyNode(node_id="n2"),
            "n3": TopologyNode(node_id="n3"),
        },
        edges=[
            TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
            TopologyEdge(edge_id="e2", upstream="n2", downstream="n3"),
        ],
    )
    assert graph.reachable("n1") == {"n2", "n3"}


def test_engine_compute_score() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={
            "n1": TopologyNode(node_id="n1", dependencies=["n2"]),
            "n2": TopologyNode(node_id="n2"),
        },
        edges=[TopologyEdge(edge_id="e1", upstream="n1", downstream="n2")],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={
            "n1": TopologyNode(node_id="n1", dependencies=["n2", "n3"]),
            "n2": TopologyNode(node_id="n2"),
            "n3": TopologyNode(node_id="n3"),
        },
        edges=[
            TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
            TopologyEdge(edge_id="e2", upstream="n1", downstream="n3"),
        ],
    )
    engine = BlastRadiusEngine()
    score = engine.compute_score(baseline, modified, "n1")
    assert score.target_node == "n1"
    assert score.dependency_expansion == 1
    assert score.input_hash != ""


def test_engine_evaluate_report_limits() -> None:
    from pi_semantic_radius.models import RiskReport, RiskScore

    engine = BlastRadiusEngine(max_dependencies_per_endpoint=2)
    report = RiskReport(
        report_id="r1",
        scores=[
            RiskScore(
                score_id="s1",
                target_node="n1",
                dependency_expansion=5,
            )
        ],
    )
    exceeded = engine.evaluate_report(report)
    assert "max_dependencies_per_endpoint" in exceeded


def test_runtime_full_pipeline() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1")},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={
            "n1": TopologyNode(node_id="n1"),
            "n2": TopologyNode(node_id="n2", mutation_class="SIDE_EFFECT_BOUND"),
        },
        edges=[TopologyEdge(edge_id="e1", upstream="n1", downstream="n2")],
    )
    runtime = RadiusRuntime()
    report = runtime.run(baseline, modified)
    assert report.report_id.startswith("radius_")
    assert report.report_hash != ""
    assert len(report.scores) == 1  # n2 is new/changed


def test_propagation_risk_pass_detects_expansion() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1")},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={
            "n1": TopologyNode(node_id="n1"),
            "n2": TopologyNode(node_id="n2"),
            "n3": TopologyNode(node_id="n3"),
            "n4": TopologyNode(node_id="n4"),
        },
        edges=[
            TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
            TopologyEdge(edge_id="e2", upstream="n1", downstream="n3"),
            TopologyEdge(edge_id="e3", upstream="n1", downstream="n4"),
        ],
    )
    engine = BlastRadiusEngine(max_dependencies_per_endpoint=2)
    pass_worker = PropagationRiskPass(engine=engine)
    result = pass_worker.execute(baseline, modified, changed_nodes={"n1"})
    assert result.status == "FAIL"
    assert any("dependency expansion" in v for v in result.violations)


def test_topology_expansion_pass_passes_clean() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1")},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={"n1": TopologyNode(node_id="n1")},
        edges=[],
    )
    pass_worker = TopologyExpansionPass()
    result = pass_worker.execute(baseline, modified)
    assert result.status == "PASS"
    assert result.violations == []


def test_auth_boundary_pass_detects_widening() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1", auth_fields=["token"])},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={"n1": TopologyNode(node_id="n1", auth_fields=["token", "otp"])},
        edges=[],
    )
    pass_worker = AuthBoundaryPass()
    result = pass_worker.execute(baseline, modified)
    assert result.status == "FAIL"
    assert any("auth fields expanded" in v for v in result.violations)


def test_replay_hazard_pass_detects_degradation() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1", replay_class="IDEMPOTENT")},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={"n1": TopologyNode(node_id="n1", replay_class="NON_REPLAYABLE")},
        edges=[],
    )
    pass_worker = ReplayHazardPass()
    result = pass_worker.execute(baseline, modified)
    assert result.status == "FAIL"
    assert any("replay class degraded" in v for v in result.violations)


def test_mutation_impact_pass_detects_escalation() -> None:
    baseline = TopologyGraph(
        graph_id="base",
        nodes={"n1": TopologyNode(node_id="n1", mutation_class="IDEMPOTENT_READ")},
        edges=[],
    )
    modified = TopologyGraph(
        graph_id="mod",
        nodes={"n1": TopologyNode(node_id="n1", mutation_class="STATEFUL_MUTATION")},
        edges=[],
    )
    pass_worker = MutationImpactPass()
    result = pass_worker.execute(baseline, modified)
    assert result.status == "FAIL"
    assert any("mutation class changed" in v for v in result.violations)


class TestReportHashReproducibility:
    """Determinism regression: the RiskReport content hash must be a pure
    function of the logical risk content, independent of wall-clock time
    (generated_at) and the random uuid-derived execution id (report_id).

    Mirrors the pi_event_fabric reference fix: the same logical input must
    reproduce the same hash across two fresh runtime instances, while the
    timestamp and unique id are still recorded as metadata.
    """

    @staticmethod
    def _graphs() -> tuple[TopologyGraph, TopologyGraph]:
        baseline = TopologyGraph(
            graph_id="base",
            nodes={"n1": TopologyNode(node_id="n1")},
            edges=[],
        )
        modified = TopologyGraph(
            graph_id="mod",
            nodes={
                "n1": TopologyNode(node_id="n1"),
                "n2": TopologyNode(node_id="n2", mutation_class="SIDE_EFFECT_BOUND"),
                "n3": TopologyNode(node_id="n3", auth_fields=["token"]),
            },
            edges=[
                TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
                TopologyEdge(edge_id="e2", upstream="n1", downstream="n3"),
            ],
        )
        return baseline, modified

    def test_report_hash_is_reproducible(self) -> None:
        baseline, modified = self._graphs()

        # Two FRESH runtime instances -> different report_id (uuid) and
        # different generated_at (wall-clock), but identical logical content.
        report_a = RadiusRuntime().run(baseline, modified)
        report_b = RadiusRuntime().run(baseline, modified)

        # Metadata that MUST differ across instances (proves they are distinct
        # objects with their own random id) -- yet must NOT affect the hash.
        assert report_a.report_id != report_b.report_id

        # The content-addressed hash must be identical.
        assert report_a.report_hash != ""
        assert report_a.report_hash == report_b.report_hash

    def test_report_hash_ignores_report_id_and_generated_at(self) -> None:
        from datetime import datetime, timezone

        from pi_semantic_radius.models import RiskReport, RiskScore

        score = RiskScore(score_id="s1", target_node="n1", dependency_expansion=3)

        report_one = RiskReport(
            report_id="radius_aaaaaaaaaaaa",
            baseline_graph_id="base",
            modified_graph_id="mod",
            scores=[score],
            generated_at=datetime(2021, 1, 1, tzinfo=timezone.utc),
        )
        report_two = RiskReport(
            report_id="radius_bbbbbbbbbbbb",
            baseline_graph_id="base",
            modified_graph_id="mod",
            scores=[score],
            generated_at=datetime(2099, 12, 31, tzinfo=timezone.utc),
        )

        # Differing report_id and generated_at must not change the hash.
        assert report_one.compute_hash() == report_two.compute_hash()

    def test_report_records_timestamp_and_unique_id(self) -> None:
        from datetime import datetime

        baseline, modified = self._graphs()
        report = RadiusRuntime().run(baseline, modified)

        # The wall-clock timestamp is still stored as metadata...
        assert isinstance(report.generated_at, datetime)
        # ...and a unique id is still recorded.
        assert report.report_id.startswith("radius_")

    def test_report_hash_changes_with_logical_content(self) -> None:
        baseline, modified = self._graphs()
        report_base = RadiusRuntime().run(baseline, modified)

        # A genuinely different logical input must yield a different hash.
        modified_more = TopologyGraph(
            graph_id="mod",
            nodes={
                "n1": TopologyNode(node_id="n1"),
                "n2": TopologyNode(node_id="n2", mutation_class="SIDE_EFFECT_BOUND"),
                "n3": TopologyNode(node_id="n3", auth_fields=["token", "otp"]),
            },
            edges=[
                TopologyEdge(edge_id="e1", upstream="n1", downstream="n2"),
                TopologyEdge(edge_id="e2", upstream="n1", downstream="n3"),
            ],
        )
        report_changed = RadiusRuntime().run(baseline, modified_more)
        assert report_base.report_hash != report_changed.report_hash
