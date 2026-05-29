"""Propagation Risk Pass.

Deterministic pass that computes propagation risk scores for topology changes.
"""

from __future__ import annotations

from typing import List, Optional, Set

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import PassResult, RiskScore, TopologyGraph


class PropagationRiskPass:
    """Deterministic propagation risk computation pass."""

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()

    def execute(
        self,
        baseline: TopologyGraph,
        modified: TopologyGraph,
        changed_nodes: Optional[Set[str]] = None,
    ) -> PassResult:
        """Execute propagation risk pass on changed nodes."""
        if changed_nodes is None:
            changed_nodes = self._detect_changed_nodes(baseline, modified)

        scores: List[RiskScore] = []
        violations: List[str] = []

        for node_id in changed_nodes:
            score = self.engine.compute_score(baseline, modified, node_id)
            scores.append(score)
            if score.dependency_expansion > self.engine.max_dependencies:
                violations.append(
                    f"Node {node_id}: dependency expansion {score.dependency_expansion} "
                    f"exceeds limit {self.engine.max_dependencies}"
                )
            if score.topology_complexity_delta > self.engine.max_complexity:
                violations.append(
                    f"Node {node_id}: complexity delta {score.topology_complexity_delta} "
                    f"exceeds limit {self.engine.max_complexity}"
                )

        return PassResult(
            pass_name="propagation_risk",
            status="FAIL" if violations else "PASS",
            violations=violations,
            evidence_count=len(scores),
        )

    def _detect_changed_nodes(self, baseline: TopologyGraph, modified: TopologyGraph) -> Set[str]:
        """Deterministically detect nodes that changed between graphs."""
        changed: Set[str] = set()
        all_nodes = set(baseline.nodes.keys()) | set(modified.nodes.keys())
        for node_id in all_nodes:
            b = baseline.nodes.get(node_id)
            m = modified.nodes.get(node_id)
            if b is None or m is None:
                changed.add(node_id)
                continue
            if b.model_dump() != m.model_dump():
                changed.add(node_id)
        return changed
