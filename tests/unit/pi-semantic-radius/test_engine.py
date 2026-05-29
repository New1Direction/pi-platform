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
