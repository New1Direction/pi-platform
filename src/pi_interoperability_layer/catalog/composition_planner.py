"""Capability Composition Planner.

Builds valid deterministic chains of workers/packages as a DAG.
Outputs execution graph only. No execution autonomy.
No LLM inference. Topological ordering with evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest
from pi_interoperability_layer.capability.graph import (
    CompatibilityVerdict,
    ExtensionCompatibilityGraph,
)


@dataclass(frozen=True)
class CompositionNode:
    """A node in the composition DAG."""

    node_id: str
    manifest_id: str
    capability_class: str
    worker_type: str
    inputs: Tuple[str, ...]  # node_ids that feed into this node


@dataclass(frozen=True)
class CompositionPlan:
    """A deterministic composition plan (DAG)."""

    plan_id: str
    nodes: Tuple[CompositionNode, ...]
    execution_order: Tuple[Tuple[str, ...], ...]  # phase-ordered groups
    valid: bool
    reason: Optional[str]
    plan_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "plan_id": self.plan_id,
                "nodes": [
                    {
                        "id": n.node_id,
                        "manifest": n.manifest_id,
                        "class": n.capability_class,
                        "worker": n.worker_type,
                        "inputs": sorted(n.inputs),
                    }
                    for n in self.nodes
                ],
                "order": [sorted(group) for group in self.execution_order],
                "valid": self.valid,
                "reason": self.reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class CapabilityCompositionPlanner:
    """Deterministic composition planner for capability chains.

    Builds DAGs of workers/packages based on:
    - CapabilityClass compatibility
    - Dependency graph edges
    - Topological constraints

    No execution. No autonomy. Graph output only.
    """

    def __init__(self, compatibility_graph: ExtensionCompatibilityGraph) -> None:
        self.graph = compatibility_graph

    def plan(
        self,
        manifests: List[ExtensionManifest],
        target_output_class: Optional[CapabilityClass] = None,
    ) -> CompositionPlan:
        """Build a deterministic composition plan from a set of manifests.

        Args:
            manifests: List of manifests to compose.
            target_output_class: Optional desired output capability class.

        Returns:
            CompositionPlan with phase-ordered execution groups.
        """
        if not manifests:
            return self._invalid_plan("No manifests provided")

        # Build nodes
        nodes: List[CompositionNode] = []
        manifest_ids = {m.extension_id for m in manifests}

        for _idx, manifest in enumerate(manifests):
            # Find dependencies within the provided set
            dep_inputs: List[str] = []
            for dep in manifest.dependencies:
                dep_id = self._find_manifest_id(dep, manifests)
                if dep_id:
                    dep_inputs.append(dep_id)

            node = CompositionNode(
                node_id=manifest.extension_id,
                manifest_id=manifest.extension_id,
                capability_class=manifest.capability_class.value,
                worker_type=f"{manifest.capability_class.value}_worker",
                inputs=tuple(sorted(set(dep_inputs))),
            )
            nodes.append(node)

        # Validate: detect cycles
        if self._has_cycle(nodes):
            return self._invalid_plan("Dependency cycle detected in composition")

        # Compute topological phases
        phases = self._topological_phases(nodes)

        # Validate compatibility across phases
        for phase in phases:
            for i, node_a in enumerate(phase):
                for node_b in phase[i + 1 :]:
                    check = self.graph.check_compatibility(node_a, node_b)
                    if check.verdict != CompatibilityVerdict.COMPATIBLE:
                        return self._invalid_plan(
                            f"Incompatible nodes in same phase: {node_a} vs {node_b}: {check.evidence}"
                        )

        plan = CompositionPlan(
            plan_id=f"plan_{hashlib.sha256(','.join(sorted(manifest_ids)).encode()).hexdigest()[:16]}",
            nodes=tuple(nodes),
            execution_order=tuple(tuple(sorted(p)) for p in phases),
            valid=True,
            reason=None,
            plan_hash="",
        )
        return CompositionPlan(
            plan_id=plan.plan_id,
            nodes=plan.nodes,
            execution_order=plan.execution_order,
            valid=plan.valid,
            reason=plan.reason,
            plan_hash=plan.compute_hash(),
        )

    def _find_manifest_id(self, dep_string: str, manifests: List[ExtensionManifest]) -> Optional[str]:
        """Find manifest ID matching a dependency string."""
        dep_name = dep_string.split("@")[0] if "@" in dep_string else dep_string
        for m in manifests:
            if m.name == dep_name or m.extension_id == dep_name:
                return m.extension_id
        return None

    def _has_cycle(self, nodes: List[CompositionNode]) -> bool:
        """DFS cycle detection."""
        graph: Dict[str, Set[str]] = {n.node_id: set(n.inputs) for n in nodes}
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)
            for neighbor in graph.get(node_id, set()):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            rec_stack.remove(node_id)
            return False

        for node in nodes:
            if node.node_id not in visited:
                if dfs(node.node_id):
                    return True
        return False

    def _topological_phases(self, nodes: List[CompositionNode]) -> List[List[str]]:
        """Kahn's algorithm for topological phase ordering."""
        in_degree: Dict[str, int] = {n.node_id: 0 for n in nodes}
        adj: Dict[str, List[str]] = {n.node_id: [] for n in nodes}

        for n in nodes:
            for inp in n.inputs:
                if inp in adj:
                    adj[inp].append(n.node_id)
                    in_degree[n.node_id] += 1

        phases: List[List[str]] = []
        while in_degree:
            zero_in = [nid for nid, deg in in_degree.items() if deg == 0]
            if not zero_in:
                break  # cycle (should be caught earlier)
            phases.append(zero_in)
            for nid in zero_in:
                del in_degree[nid]
                for neighbor in adj.get(nid, []):
                    if neighbor in in_degree:
                        in_degree[neighbor] -= 1

        return phases

    def _invalid_plan(self, reason: str) -> CompositionPlan:
        return CompositionPlan(
            plan_id="invalid",
            nodes=(),
            execution_order=(),
            valid=False,
            reason=reason,
            plan_hash=hashlib.sha256(reason.encode()).hexdigest(),
        )
