"""Auth Boundary Pass.

Deterministic pass that detects auth surface widening.
"""

from __future__ import annotations

from typing import List, Optional

from pi_semantic_radius.engine import BlastRadiusEngine
from pi_semantic_radius.models import PassResult, TopologyGraph


class AuthBoundaryPass:
    """Deterministic auth boundary widening pass."""

    def __init__(self, engine: Optional[BlastRadiusEngine] = None) -> None:
        self.engine = engine or BlastRadiusEngine()

    def execute(self, baseline: TopologyGraph, modified: TopologyGraph) -> PassResult:
        """Execute auth boundary pass."""
        violations: List[str] = []

        for node_id, mod_node in modified.nodes.items():
            base_node = baseline.nodes.get(node_id)
            base_auth = len(base_node.auth_fields) if base_node else 0
            mod_auth = len(mod_node.auth_fields)
            if mod_auth - base_auth > 0:
                violations.append(f"Node {node_id} auth fields expanded by {mod_auth - base_auth}")
            if mod_auth > self.engine.max_auth_fields:
                violations.append(f"Node {node_id} auth fields {mod_auth} exceed limit {self.engine.max_auth_fields}")

        return PassResult(
            pass_name="auth_boundary",
            status="FAIL" if violations else "PASS",
            violations=violations,
            evidence_count=len(modified.nodes),
        )
