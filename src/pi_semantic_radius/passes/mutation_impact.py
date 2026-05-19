"""Mutation Impact Pass.

Deterministic pass that detects downstream mutation impact.
"""

from __future__ import annotations

from typing import List

from pi_semantic_radius.models import PassResult, TopologyGraph
from pi_semantic_radius.engine import BlastRadiusEngine


class MutationImpactPass:
    """Deterministic downstream mutation impact pass."""

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()

    def execute(self, baseline: TopologyGraph, modified: TopologyGraph) -> PassResult:
        """Execute mutation impact pass."""
        violations: List[str] = []

        # Side-effect-bound expansion
        base_se = sum(1 for n in baseline.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        mod_se = sum(1 for n in modified.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        if mod_se - base_se > 0:
            violations.append(
                f"Side-effect-bound endpoints expanded by {mod_se - base_se}"
            )
        if mod_se > self.engine.max_side_effect:
            violations.append(
                f"Side-effect-bound endpoints {mod_se} exceed limit {self.engine.max_side_effect}"
            )

        # Downstream mutation escalation
        for node_id, mod_node in modified.nodes.items():
            base_node = baseline.nodes.get(node_id)
            if base_node is None:
                continue
            if base_node.mutation_class != mod_node.mutation_class:
                violations.append(
                    f"Node {node_id} mutation class changed from {base_node.mutation_class} "
                    f"to {mod_node.mutation_class}"
                )

        return PassResult(
            pass_name="mutation_impact",
            status="FAIL" if violations else "PASS",
            violations=violations,
            evidence_count=len(modified.nodes),
        )
