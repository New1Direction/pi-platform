"""Blast Radius Runtime.

Formalized topology propagation scoring, dependency expansion mapping,
replay propagation analysis, auth surface growth tracking.

No inference. No probabilistic risk scores. No speculative impact analysis.
All scoring is deterministic and bounded.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Topology Primitives
# ──────────────────────────────


class TopologyNode(BaseModel):
    """A single node in the dependency topology."""

    node_id: str
    node_type: str = "UNKNOWN"  # e.g. "endpoint", "service", "database", "queue"
    # Direct dependencies (outgoing edges)
    dependencies: List[str] = Field(default_factory=list)
    # Auth fields attached to this node
    auth_fields: List[str] = Field(default_factory=list)
    # Mutation classification
    mutation_class: str = "UNKNOWN"
    # Replay classification
    replay_class: str = "UNKNOWN"
    # Layer assignment
    layer_id: str = ""
    model_config = {"frozen": True}


class TopologyEdge(BaseModel):
    """A directed edge in the dependency topology."""

    edge_id: str
    upstream: str
    downstream: str
    edge_type: str = "UNKNOWN"  # e.g. "direct_call", "async_event", "shared_state"
    # Auth carrier
    carries_auth: bool = False
    # State mutation carrier
    carries_state: bool = False
    model_config = {"frozen": True}


class TopologyGraph(BaseModel):
    """Immutable topology graph for blast radius computation."""

    graph_id: str
    nodes: Dict[str, TopologyNode] = Field(default_factory=dict)
    edges: List[TopologyEdge] = Field(default_factory=list)
    model_config = {"frozen": True}

    def fanout(self, node_id: str) -> int:
        """Count direct outgoing edges from a node."""
        return sum(1 for e in self.edges if e.upstream == node_id)

    def depth_from(self, node_id: str, visited: Optional[Set[str]] = None) -> int:
        """Compute max depth from node following outgoing edges (bounded)."""
        visited = visited or set()
        if node_id in visited:
            return 0
        visited.add(node_id)
        children = [e.downstream for e in self.edges if e.upstream == node_id]
        if not children:
            return 0
        return 1 + max(
            (self.depth_from(child, visited.copy()) for child in children),
            default=0,
        )

    def reachable_nodes(self, node_id: str) -> Set[str]:
        """All nodes reachable from node_id via outgoing edges."""
        visited: Set[str] = set()
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            if current in visited:
                continue
            visited.add(current)
            for e in self.edges:
                if e.upstream == current and e.downstream not in visited:
                    frontier.append(e.downstream)
        visited.discard(node_id)
        return visited


# ──────────────────────────────
#  Blast Radius Models
# ──────────────────────────────


class BlastRadiusScore(BaseModel):
    """Deterministic blast radius score for a topology change."""

    score_id: str
    target_node: str
    # Topology metrics
    dependency_expansion: int  # new dependencies added
    topology_complexity_delta: float  # change in complexity score
    fanout_delta: int  # change in max fanout
    depth_delta: int  # change in max depth
    # Auth surface metrics
    auth_surface_expansion: int  # new auth fields added
    auth_invariant_delta: int  # change in auth invariant count
    unconfirmed_auth_delta: int  # change in unconfirmed auth bindings
    # Replay propagation metrics
    replay_scope_expansion: int  # new nodes added to replay scope
    replay_propagation_depth: int  # depth of replay propagation
    side_effect_bound_delta: int  # change in side-effect-bound endpoints
    # Drift metrics
    structural_delta: float
    semantic_delta: float
    drift_score: float
    # Deterministic hash of all inputs
    input_hash: str = ""
    model_config = {"frozen": True}


class BlastRadiusReport(BaseModel):
    """Aggregated blast radius report for a set of changes."""

    report_id: str
    scores: List[BlastRadiusScore] = Field(default_factory=list)
    # Aggregate bounds
    total_dependency_expansion: int = 0
    total_auth_surface_expansion: int = 0
    total_replay_scope_expansion: int = 0
    max_drift_score: float = 0.0
    # Policy limit checks
    limits_exceeded: List[str] = Field(default_factory=list)
    # Deterministic report hash
    report_hash: str = ""
    model_config = {"frozen": True}


# ──────────────────────────────
#  Blast Radius Engine
# ──────────────────────────────


class BlastRadiusEngine(BaseModel):
    """Deterministic blast radius computation engine.

    Computes bounded, evidence-bound blast radius metrics for topology changes.
    """

    engine_id: str
    # Numeric limits
    max_dependencies_per_endpoint: int = Field(default=16, ge=0)
    max_cross_service_edges: int = Field(default=64, ge=0)
    max_fanout_per_endpoint: int = Field(default=8, ge=0)
    max_graph_depth: int = Field(default=6, ge=0)
    max_topology_complexity_score: float = Field(default=100.0, ge=0.0)
    max_auth_fields_per_endpoint: int = Field(default=8, ge=0)
    max_auth_invariants_per_graph: int = Field(default=128, ge=0)
    max_unconfirmed_auth_bindings: int = Field(default=32, ge=0)
    max_replay_scope_nodes: int = Field(default=256, ge=0)
    max_replay_propagation_depth: int = Field(default=6, ge=0)
    max_side_effect_bound_endpoints: int = Field(default=32, ge=0)
    max_structural_delta: float = Field(default=0.3, ge=0.0, le=1.0)
    max_semantic_delta: float = Field(default=0.3, ge=0.0, le=1.0)
    max_drift_score: float = Field(default=0.2, ge=0.0, le=1.0)
    model_config = {"frozen": True}

    def compute_score(
        self,
        baseline: TopologyGraph,
        modified: TopologyGraph,
        target_node: str,
    ) -> BlastRadiusScore:
        """Compute deterministic blast radius score for a topology change."""
        # Topology deltas
        baseline_reachable = baseline.reachable_nodes(target_node)
        modified_reachable = modified.reachable_nodes(target_node)
        dep_expansion = len(modified_reachable - baseline_reachable)

        base_complexity = self._complexity_score(baseline)
        mod_complexity = self._complexity_score(modified)
        complexity_delta = mod_complexity - base_complexity

        base_fanout = max((baseline.fanout(n) for n in baseline.nodes.keys()), default=0)
        mod_fanout = max((modified.fanout(n) for n in modified.nodes.keys()), default=0)
        fanout_delta = mod_fanout - base_fanout

        base_depth = max((baseline.depth_from(n) for n in baseline.nodes.keys()), default=0)
        mod_depth = max((modified.depth_from(n) for n in modified.nodes.keys()), default=0)
        depth_delta = mod_depth - base_depth

        # Auth surface deltas
        base_auth = sum(len(n.auth_fields) for n in baseline.nodes.values())
        mod_auth = sum(len(n.auth_fields) for n in modified.nodes.values())
        auth_surface_expansion = mod_auth - base_auth

        # Replay scope deltas
        replay_scope_expansion = len(modified_reachable - baseline_reachable)
        replay_propagation_depth = mod_depth

        # Side-effect bound
        base_se = sum(1 for n in baseline.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        mod_se = sum(1 for n in modified.nodes.values() if n.mutation_class == "SIDE_EFFECT_BOUND")
        side_effect_delta = mod_se - base_se

        # Deterministic input hash
        inputs = {
            "baseline_nodes": sorted(baseline.nodes.keys()),
            "modified_nodes": sorted(modified.nodes.keys()),
            "target_node": target_node,
        }
        input_hash = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        return BlastRadiusScore(
            score_id=f"br_{target_node}_{input_hash[:16]}",
            target_node=target_node,
            dependency_expansion=dep_expansion,
            topology_complexity_delta=round(complexity_delta, 6),
            fanout_delta=fanout_delta,
            depth_delta=depth_delta,
            auth_surface_expansion=auth_surface_expansion,
            auth_invariant_delta=0,  # requires external invariant count
            unconfirmed_auth_delta=0,  # requires external binding count
            replay_scope_expansion=replay_scope_expansion,
            replay_propagation_depth=replay_propagation_depth,
            side_effect_bound_delta=side_effect_delta,
            structural_delta=0.0,
            semantic_delta=0.0,
            drift_score=0.0,
            input_hash=input_hash,
        )

    def _complexity_score(self, graph: TopologyGraph) -> float:
        """Bounded deterministic topology complexity score."""
        node_count = len(graph.nodes)
        edge_count = len(graph.edges)
        max_fanout = max((graph.fanout(n) for n in graph.nodes.keys()), default=0)
        max_depth = max((graph.depth_from(n) for n in graph.nodes.keys()), default=0)
        # Deterministic formula: nodes + edges + fanout^2 + depth^2
        return float(node_count + edge_count + (max_fanout**2) + (max_depth**2))

    def evaluate_report(self, report: BlastRadiusReport) -> List[str]:
        """Evaluate report against limits; return list of exceeded limit names."""
        exceeded: List[str] = []
        max_dep = max((s.dependency_expansion for s in report.scores), default=0)
        if max_dep > self.max_dependencies_per_endpoint:
            exceeded.append("max_dependencies_per_endpoint")
        max_fan = max((s.fanout_delta for s in report.scores), default=0)
        if max_fan > self.max_fanout_per_endpoint:
            exceeded.append("max_fanout_per_endpoint")
        max_depth = max((s.depth_delta for s in report.scores), default=0)
        if max_depth > self.max_graph_depth:
            exceeded.append("max_graph_depth")
        max_auth = max((s.auth_surface_expansion for s in report.scores), default=0)
        if max_auth > self.max_auth_fields_per_endpoint:
            exceeded.append("max_auth_fields_per_endpoint")
        max_replay = max((s.replay_scope_expansion for s in report.scores), default=0)
        if max_replay > self.max_replay_scope_nodes:
            exceeded.append("max_replay_scope_nodes")
        max_drift = max((s.drift_score for s in report.scores), default=0.0)
        if max_drift > self.max_drift_score:
            exceeded.append("max_drift_score")
        return exceeded
