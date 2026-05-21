"""Core Radius Runtime.

Deterministic propagation risk worker.
Orchestrates all blast radius passes and produces a RiskReport.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Set

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import PassResult, RiskReport, TopologyGraph
from pi_semantic_radius.passes.auth_boundary import AuthBoundaryPass
from pi_semantic_radius.passes.mutation_impact import MutationImpactPass
from pi_semantic_radius.passes.propagation_risk import PropagationRiskPass
from pi_semantic_radius.passes.replay_hazard import ReplayHazardPass
from pi_semantic_radius.passes.topology_expansion import TopologyExpansionPass


class RadiusRuntime:
    """Deterministic propagation risk runtime.

    f(baseline_graph, modified_graph) -> RiskReport
    """

    PASS_ORDER = [
        ("propagation_risk", PropagationRiskPass),
        ("topology_expansion", TopologyExpansionPass),
        ("auth_boundary", AuthBoundaryPass),
        ("replay_hazard", ReplayHazardPass),
        ("mutation_impact", MutationImpactPass),
    ]

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()
        self._execution_id = f"radius_{uuid.uuid4().hex[:12]}"

    @property
    def execution_id(self) -> str:
        return self._execution_id

    def run(
        self,
        baseline: TopologyGraph,
        modified: TopologyGraph,
        changed_nodes: Optional[Set[str]] = None,
    ) -> RiskReport:
        """Execute all blast radius passes in fixed order."""
        pass_results: List[PassResult] = []
        all_violations: List[str] = []

        for pass_name, pass_cls in self.PASS_ORDER:
            try:
                worker = pass_cls(engine=self.engine)
                if pass_name == "propagation_risk":
                    result = worker.execute(baseline, modified, changed_nodes)
                else:
                    result = worker.execute(baseline, modified)
                pass_results.append(result)
                all_violations.extend(result.violations)
            except Exception as exc:
                pass_results.append(
                    PassResult(
                        pass_name=pass_name,
                        status="FAIL",
                        violations=[f"PASS_EXECUTION_FAILURE: {exc}"],
                        evidence_count=0,
                    )
                )

        # Compute scores for changed nodes
        scores = []
        if changed_nodes is None:
            changed_nodes = self._detect_changed_nodes(baseline, modified)
        for node_id in changed_nodes:
            score = self.engine.compute_score(baseline, modified, node_id)
            scores.append(score)

        # Aggregates
        total_dep = sum(s.dependency_expansion for s in scores)
        total_auth = sum(s.auth_surface_expansion for s in scores)
        total_replay = sum(s.replay_hazard_spread for s in scores)
        total_mut = sum(s.downstream_mutation_impact for s in scores)
        max_depth = max((s.depth_delta for s in scores), default=0)
        max_fan = max((s.fanout_delta for s in scores), default=0)

        limits = self.engine.evaluate_report(
            RiskReport(
                report_id="",
                baseline_graph_id=baseline.graph_id,
                modified_graph_id=modified.graph_id,
                scores=scores,
            )
        )

        report = RiskReport(
            report_id=self._execution_id,
            baseline_graph_id=baseline.graph_id,
            modified_graph_id=modified.graph_id,
            scores=scores,
            total_dependency_expansion=total_dep,
            total_auth_surface_expansion=total_auth,
            total_replay_hazard_spread=total_replay,
            total_downstream_mutation_impact=total_mut,
            max_topology_depth_delta=max_depth,
            max_fanout_delta=max_fan,
            limits_exceeded=limits,
            generated_at=datetime.now(timezone.utc),
        )
        report_hash = report.compute_hash()
        return report.model_copy(update={"report_hash": report_hash})

    def _detect_changed_nodes(self, baseline: TopologyGraph, modified: TopologyGraph) -> Set[str]:
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
