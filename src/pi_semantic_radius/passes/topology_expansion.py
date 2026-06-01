"""Topology Expansion Pass.

Deterministic pass that detects topology growth violations.
"""

from __future__ import annotations

from typing import List, Optional

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import PassResult, TopologyGraph


class TopologyExpansionPass:
    """Deterministic topology expansion pass."""

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()

    def execute(self, baseline: TopologyGraph, modified: TopologyGraph) -> PassResult:
        """Execute topology expansion pass."""
        violations: List[str] = []

        # Node count expansion
        node_delta = len(modified.nodes) - len(baseline.nodes)
        if node_delta > 0:
            violations.append(f"Node count expanded by {node_delta}")

        # Edge count expansion
        edge_delta = len(modified.edges) - len(baseline.edges)
        if edge_delta > self.engine.max_cross_service:
            violations.append(f"Edge count expanded by {edge_delta} exceeds limit {self.engine.max_cross_service}")

        # Fanout expansion per node
        for node_id in modified.nodes:
            base_fan = baseline.fanout(node_id)
            mod_fan = modified.fanout(node_id)
            if mod_fan - base_fan > self.engine.max_fanout:
                violations.append(
                    f"Node {node_id} fanout expanded by {mod_fan - base_fan} exceeds limit {self.engine.max_fanout}"
                )

        # Depth expansion
        for node_id in modified.nodes:
            base_depth = baseline.depth_from(node_id)
            mod_depth = modified.depth_from(node_id)
            if mod_depth - base_depth > self.engine.max_depth:
                violations.append(
                    f"Node {node_id} depth expanded by {mod_depth - base_depth} exceeds limit {self.engine.max_depth}"
                )

        return PassResult(
            pass_name="topology_expansion",
            status="FAIL" if violations else "PASS",
            violations=violations,
            evidence_count=len(modified.nodes),
        )
