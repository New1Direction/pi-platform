"""Replay Hazard Pass.

Deterministic pass that detects replay hazard spread.
"""

from __future__ import annotations

from typing import List, Optional, Set

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import PassResult, TopologyGraph


class ReplayHazardPass:
    """Deterministic replay hazard spread pass."""

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()

    def execute(self, baseline: TopologyGraph, modified: TopologyGraph) -> PassResult:
        """Execute replay hazard spread pass."""
        violations: List[str] = []
        all_nodes: Set[str] = set(modified.nodes.keys())

        for node_id in all_nodes:
            base_node = baseline.nodes.get(node_id)
            mod_node = modified.nodes.get(node_id)
            b_replay = base_node.replay_class if base_node else "UNKNOWN"
            m_replay = mod_node.replay_class if mod_node else "UNKNOWN"

            # Degradation: replayable -> non-replayable
            if b_replay in ("PURE_REPLAYABLE", "IDEMPOTENT") and m_replay in ("NON_REPLAYABLE", "SIDE_EFFECT_RISK"):
                violations.append(f"Node {node_id} replay class degraded from {b_replay} to {m_replay}")

            # Propagation depth check
            reachable = modified.reachable(node_id)
            if len(reachable) > self.engine.max_replay_scope:
                violations.append(
                    f"Node {node_id} replay scope {len(reachable)} exceeds limit {self.engine.max_replay_scope}"
                )

        return PassResult(
            pass_name="replay_hazard",
            status="FAIL" if violations else "PASS",
            violations=violations,
            evidence_count=len(all_nodes),
        )
