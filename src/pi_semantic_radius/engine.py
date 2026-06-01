"""Bounded blast radius computation engine.

Deterministic propagation risk scoring.
No inference. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
from typing import List

from pi_semantic_radius.models import RiskReport, RiskScore, TopologyGraph


class BlastRadiusEngine:
    """Deterministic blast radius computation engine.

    Computes bounded, evidence-bound blast radius metrics for topology changes.
    """

    def __init__(
        self,
        max_dependencies_per_endpoint: int = 16,
        max_cross_service_edges: int = 64,
        max_fanout_per_endpoint: int = 8,
        max_graph_depth: int = 6,
        max_topology_complexity_score: float = 100.0,
        max_auth_fields_per_endpoint: int = 8,
        max_replay_scope_nodes: int = 256,
        max_replay_propagation_depth: int = 6,
        max_side_effect_bound_endpoints: int = 32,
    ) -> None:
        self.max_dependencies = max_dependencies_per_endpoint
        self.max_cross_service = max_cross_service_edges
        self.max_fanout = max_fanout_per_endpoint
        self.max_depth = max_graph_depth
        self.max_complexity = max_topology_complexity_score
        self.max_auth_fields = max_auth_fields_per_endpoint
        self.max_replay_scope = max_replay_scope_nodes
        self.max_replay_depth = max_replay_propagation_depth
        self.max_side_effect = max_side_effect_bound_endpoints

    def _complexity_score(self, graph: TopologyGraph) -> float:
        """Bounded deterministic topology complexity score."""
        node_count = len(graph.nodes)
        edge_count = len(graph.edges)
        max_fanout = max(
            (graph.fanout(n) for n in graph.nodes.keys()),
            default=0,
        )
        max_depth = max(
            (graph.depth_from(n) for n in graph.nodes.keys()),
            default=0,
        )
        return float(node_count + edge_count + (max_fanout**2) + (max_depth**2))

    def compute_score(
        self,
        baseline: TopologyGraph,
        modified: TopologyGraph,
        target_node: str,
    ) -> RiskScore:
        """Compute deterministic blast radius score for a topology change."""
        # Topology deltas
        baseline_reachable = baseline.reachable(target_node)
        modified_reachable = modified.reachable(target_node)
        dep_expansion = len(modified_reachable - baseline_reachable)

        base_complexity = self._complexity_score(baseline)
        mod_complexity = self._complexity_score(modified)
        complexity_delta = mod_complexity - base_complexity

        base_fanout = max(
            (baseline.fanout(n) for n in baseline.nodes.keys()),
            default=0,
        )
        mod_fanout = max(
            (modified.fanout(n) for n in modified.nodes.keys()),
            default=0,
        )
        fanout_delta = mod_fanout - base_fanout

        base_depth = max(
            (baseline.depth_from(n) for n in baseline.nodes.keys()),
            default=0,
        )
        mod_depth = max(
            (modified.depth_from(n) for n in modified.nodes.keys()),
            default=0,
        )
        depth_delta = mod_depth - base_depth

        # Auth surface
        base_auth = sum(len(n.auth_fields) for n in baseline.nodes.values())
        mod_auth = sum(len(n.auth_fields) for n in modified.nodes.values())
        auth_expansion = mod_auth - base_auth
        auth_widening = auth_expansion > 0

        # Replay hazard
        replay_spread = len(modified_reachable - baseline_reachable)
        replay_depth = mod_depth

        # Mutation impact
        base_se = sum(1 for n in baseline.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        mod_se = sum(1 for n in modified.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        se_delta = mod_se - base_se

        # Downstream mutation impact: count of reachable nodes with mutation class escalation
        downstream_impact = 0
        for node_id in modified_reachable:
            b_node = baseline.nodes.get(node_id)
            m_node = modified.nodes.get(node_id)
            if b_node and m_node:
                if b_node.mutation_class != m_node.mutation_class:
                    downstream_impact += 1

        # Deterministic input hash
        inputs = {
            "baseline_nodes": sorted(baseline.nodes.keys()),
            "modified_nodes": sorted(modified.nodes.keys()),
            "target_node": target_node,
        }
        input_hash = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        return RiskScore(
            score_id=f"br_{target_node}_{input_hash[:16]}",
            target_node=target_node,
            dependency_expansion=dep_expansion,
            topology_complexity_delta=round(complexity_delta, 6),
            fanout_delta=fanout_delta,
            depth_delta=depth_delta,
            auth_surface_expansion=auth_expansion,
            auth_boundary_widening=auth_widening,
            replay_hazard_spread=replay_spread,
            replay_propagation_depth=replay_depth,
            downstream_mutation_impact=downstream_impact,
            side_effect_bound_expansion=se_delta,
            input_hash=input_hash,
        )

    def evaluate_report(self, report: RiskReport) -> List[str]:
        """Evaluate report against limits; return exceeded limit names."""
        exceeded: List[str] = []
        max_dep = max((s.dependency_expansion for s in report.scores), default=0)
        if max_dep > self.max_dependencies:
            exceeded.append("max_dependencies_per_endpoint")
        max_fan = max((s.fanout_delta for s in report.scores), default=0)
        if max_fan > self.max_fanout:
            exceeded.append("max_fanout_per_endpoint")
        max_depth = max((s.depth_delta for s in report.scores), default=0)
        if max_depth > self.max_depth:
            exceeded.append("max_graph_depth")
        max_auth = max((s.auth_surface_expansion for s in report.scores), default=0)
        if max_auth > self.max_auth_fields:
            exceeded.append("max_auth_fields_per_endpoint")
        max_replay = max((s.replay_hazard_spread for s in report.scores), default=0)
        if max_replay > self.max_replay_scope:
            exceeded.append("max_replay_scope_nodes")
        return exceeded
