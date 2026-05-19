"""Tests for blast radius runtime."""

from __future__ import annotations

import pytest

from pi_interoperability_layer.blast_radius import (
    TopologyNode,
    TopologyEdge,
    TopologyGraph,
    BlastRadiusScore,
    BlastRadiusReport,
    BlastRadiusEngine,
)


def test_topology_graph_fanout() -> None:
    n1 = TopologyNode(node_id="n1", dependencies=["n2", "n3"])
    n2 = TopologyNode(node_id="n2")
    n3 = TopologyNode(node_id="n3")
    e1 = TopologyEdge(edge_id="e1", upstream="n1", downstream="n2")
    e2 = TopologyEdge(edge_id="e2", upstream="n1", downstream="n3")
    graph = TopologyGraph(
        graph_id="g1", nodes={"n1": n1, "n2": n2, "n3": n3}, edges=[e1, e2]
    )
    assert graph.fanout("n1") == 2
    assert graph.fanout("n2") == 0


def test_topology_graph_depth() -> None:
    n1 = TopologyNode(node_id="n1")
    n2 = TopologyNode(node_id="n2")
    n3 = TopologyNode(node_id="n3")
    e1 = TopologyEdge(edge_id="e1", upstream="n1", downstream="n2")
    e2 = TopologyEdge(edge_id="e2", upstream="n2", downstream="n3")
    graph = TopologyGraph(
        graph_id="g1", nodes={"n1": n1, "n2": n2, "n3": n3}, edges=[e1, e2]
    )
    assert graph.depth_from("n1") == 2
    assert graph.depth_from("n2") == 1
    assert graph.depth_from("n3") == 0


def test_topology_graph_reachable() -> None:
    n1 = TopologyNode(node_id="n1")
    n2 = TopologyNode(node_id="n2")
    n3 = TopologyNode(node_id="n3")
    e1 = TopologyEdge(edge_id="e1", upstream="n1", downstream="n2")
    e2 = TopologyEdge(edge_id="e2", upstream="n2", downstream="n3")
    graph = TopologyGraph(
        graph_id="g1", nodes={"n1": n1, "n2": n2, "n3": n3}, edges=[e1, e2]
    )
    reachable = graph.reachable_nodes("n1")
    assert reachable == {"n2", "n3"}


def test_blast_radius_engine_compute_score() -> None:
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
    engine = BlastRadiusEngine(engine_id="br1")
    score = engine.compute_score(baseline, modified, "n1")
    assert score.target_node == "n1"
    assert score.dependency_expansion == 1  # n3 is new
    assert score.input_hash != ""


def test_blast_radius_engine_evaluate_report_limits() -> None:
    engine = BlastRadiusEngine(
        engine_id="br1",
        max_dependencies_per_endpoint=2,
        max_fanout_per_endpoint=2,
    )
    report = BlastRadiusReport(
        report_id="r1",
        scores=[
            BlastRadiusScore(
                score_id="s1",
                target_node="n1",
                dependency_expansion=5,
                topology_complexity_delta=0.0,
                fanout_delta=0,
                depth_delta=0,
                auth_surface_expansion=0,
                auth_invariant_delta=0,
                unconfirmed_auth_delta=0,
                replay_scope_expansion=0,
                replay_propagation_depth=0,
                side_effect_bound_delta=0,
                structural_delta=0.0,
                semantic_delta=0.0,
                drift_score=0.0,
            )
        ],
    )
    exceeded = engine.evaluate_report(report)
    assert "max_dependencies_per_endpoint" in exceeded


def test_blast_radius_score_deterministic_hash() -> None:
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
    engine = BlastRadiusEngine(engine_id="br1")
    s1 = engine.compute_score(baseline, modified, "n1")
    s2 = engine.compute_score(baseline, modified, "n1")
    assert s1.input_hash == s2.input_hash
