"""Risk Propagation Graph & Drift Simulation Engine.

Deterministic blast-radius propagation from SemanticDriftReport into
the topology space. Extends existing TopologyGraph with drift-specific
propagation semantics.

No probabilistic reasoning. All propagation is rule-based, bounded, and
fully deterministic.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Tuple

from pydantic import BaseModel, Field

from pi_interoperability_layer.blast_radius import TopologyGraph
from pi_interoperability_layer.workers.pi_observability_diff_worker import DeltaType, SemanticDelta, SemanticDriftReport

# ──────────────────────────────
#  Propagation Primitives
# ──────────────────────────────


class RiskNode(BaseModel):
    """A node in the risk propagation graph annotated with drift impact."""

    node_id: str
    node_type: str = "UNKNOWN"
    # Direct deltas affecting this node
    direct_deltas: List[str] = Field(default_factory=list)  # delta_ids
    # Propagated deltas from upstream
    propagated_deltas: List[str] = Field(default_factory=list)
    # Cumulative risk level
    risk_level: str = "NONE"  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    # Depth from nearest direct delta
    propagation_depth: int = 0
    # Whether this node is in the direct blast radius
    in_direct_blast_radius: bool = False
    model_config = {"frozen": True}


class RiskEdge(BaseModel):
    """A directed edge in the risk propagation graph with carrier flags."""

    edge_id: str
    upstream: str
    downstream: str
    edge_type: str = "UNKNOWN"
    carries_auth: bool = False
    carries_state: bool = False
    carries_drift: bool = False  # True if this edge propagates drift
    model_config = {"frozen": True}


class RiskPropagationGraph(BaseModel):
    """Immutable risk propagation graph derived from topology + drift report.

    Deterministic construction: same TopologyGraph + same SemanticDriftReport
    always produces identical RiskPropagationGraph.
    """

    graph_id: str
    topology_graph_id: str
    drift_report_id: str
    nodes: Dict[str, RiskNode] = Field(default_factory=dict)
    edges: List[RiskEdge] = Field(default_factory=list)
    # Aggregate metrics
    total_nodes_at_risk: int = 0
    total_edges_propagating: int = 0
    max_propagation_depth: int = 0
    critical_nodes: List[str] = Field(default_factory=list)
    high_nodes: List[str] = Field(default_factory=list)
    # Deterministic hash
    graph_hash: str = ""
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.graph_hash:
            object.__setattr__(self, "graph_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "graph_id": self.graph_id,
            "topology_graph_id": self.topology_graph_id,
            "drift_report_id": self.drift_report_id,
            "node_ids": sorted(self.nodes.keys()),
            "edge_signatures": sorted([f"{e.upstream}->{e.downstream}:{e.carries_drift}" for e in self.edges]),
            "total_nodes_at_risk": self.total_nodes_at_risk,
            "max_propagation_depth": self.max_propagation_depth,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


# ──────────────────────────────
#  Simulation Engine
# ──────────────────────────────


class DriftPropagationEngine:
    """Deterministic drift propagation simulation engine.

    Propagates risk from direct delta sites through the topology graph
    following deterministic rules. Bounded depth, no probabilistic scoring.
    """

    def __init__(
        self,
        max_propagation_depth: int = 6,
        auth_propagation_multiplier: int = 2,
        state_propagation_multiplier: int = 1,
    ) -> None:
        self.max_propagation_depth = max_propagation_depth
        self.auth_multiplier = auth_propagation_multiplier
        self.state_multiplier = state_propagation_multiplier

    def simulate(
        self,
        topology: TopologyGraph,
        drift_report: SemanticDriftReport,
    ) -> RiskPropagationGraph:
        """Simulate drift propagation through topology.

        Returns an immutable RiskPropagationGraph with deterministic risk
        annotations on every reachable node.
        """
        # Build risk nodes from topology nodes
        risk_nodes: Dict[str, RiskNode] = {}
        for nid, tnode in topology.nodes.items():
            risk_nodes[nid] = RiskNode(
                node_id=nid,
                node_type=tnode.node_type,
                risk_level="NONE",
                propagation_depth=0,
                in_direct_blast_radius=False,
            )

        # Build risk edges from topology edges
        risk_edges: List[RiskEdge] = []
        for e in topology.edges:
            risk_edges.append(
                RiskEdge(
                    edge_id=e.edge_id,
                    upstream=e.upstream,
                    downstream=e.downstream,
                    edge_type=e.edge_type,
                    carries_auth=e.carries_auth,
                    carries_state=e.carries_state,
                    carries_drift=False,
                )
            )

        # Map delta paths to affected node IDs
        direct_delta_nodes = self._map_deltas_to_nodes(drift_report.deltas, topology)

        # Mark direct blast radius
        for nid, delta_ids in direct_delta_nodes.items():
            if nid in risk_nodes:
                risk_nodes[nid] = risk_nodes[nid].model_copy(
                    update={
                        "direct_deltas": delta_ids,
                        "in_direct_blast_radius": True,
                        "risk_level": self._max_risk_level(
                            [self._delta_risk_level(did, drift_report) for did in delta_ids]
                        ),
                        "propagation_depth": 0,
                    }
                )

        # Propagate through topology (bounded BFS)
        for depth in range(1, self.max_propagation_depth + 1):
            frontier = self._propagation_frontier(risk_nodes, risk_edges, depth)
            for nid, incoming_deltas, edge in frontier:
                if nid not in risk_nodes:
                    continue
                existing = risk_nodes[nid]
                if existing.in_direct_blast_radius and existing.propagation_depth == 0:
                    continue  # direct nodes keep their original risk

                new_propagated = list(set(existing.propagated_deltas) | set(incoming_deltas))
                # Risk level decays by depth but auth/state edges amplify
                incoming_risk = self._propagated_risk_level(incoming_deltas, drift_report, depth, edge)
                merged_risk = self._max_risk_level([existing.risk_level, incoming_risk])

                risk_nodes[nid] = existing.model_copy(
                    update={
                        "propagated_deltas": new_propagated,
                        "risk_level": merged_risk,
                        "propagation_depth": min(existing.propagation_depth, depth)
                        if existing.propagation_depth > 0
                        else depth,
                    }
                )

        # Mark drift-carrying edges
        for i, re in enumerate(risk_edges):
            if re.downstream in risk_nodes and risk_nodes[re.downstream].risk_level != "NONE":
                risk_edges[i] = re.model_copy(update={"carries_drift": True})

        # Aggregate metrics
        total_at_risk = sum(1 for n in risk_nodes.values() if n.risk_level != "NONE")
        total_propagating = sum(1 for e in risk_edges if e.carries_drift)
        max_depth = max((n.propagation_depth for n in risk_nodes.values()), default=0)
        critical = sorted([n.node_id for n in risk_nodes.values() if n.risk_level == "CRITICAL"])
        high = sorted([n.node_id for n in risk_nodes.values() if n.risk_level == "HIGH"])

        graph_id = f"risk_{topology.graph_id}_{drift_report.report_id}"

        return RiskPropagationGraph(
            graph_id=graph_id,
            topology_graph_id=topology.graph_id,
            drift_report_id=drift_report.report_id,
            nodes=risk_nodes,
            edges=risk_edges,
            total_nodes_at_risk=total_at_risk,
            total_edges_propagating=total_propagating,
            max_propagation_depth=max_depth,
            critical_nodes=critical,
            high_nodes=high,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _map_deltas_to_nodes(
        self,
        deltas: List[SemanticDelta],
        topology: TopologyGraph,
    ) -> Dict[str, List[str]]:
        """Map delta paths to topology node IDs."""
        mapping: Dict[str, List[str]] = {}
        for d in deltas:
            # Extract node ID from path: e.g., "nodes.service_a" -> "service_a"
            parts = d.path.split(".")
            if len(parts) >= 2 and parts[0] in ("nodes", "trust_zones", "capabilities"):
                nid = parts[1]
                if nid in topology.nodes:
                    mapping.setdefault(nid, []).append(d.delta_id)
            elif d.delta_type in (
                DeltaType.TOPOLOGY_EXPANDED,
                DeltaType.TOPOLOGY_CONTRACTED,
                DeltaType.TOPOLOGY_REWIRED,
            ):
                # Topology-wide deltas affect all nodes
                for nid in topology.nodes:
                    mapping.setdefault(nid, []).append(d.delta_id)
        return mapping

    def _delta_risk_level(self, delta_id: str, report: SemanticDriftReport) -> str:
        for d in report.deltas:
            if d.delta_id == delta_id:
                return d.severity
        return "INFO"

    def _max_risk_level(self, levels: List[str]) -> str:
        order = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        max_level = max(levels, key=lambda lvl: order.get(lvl, 0))
        return max_level

    def _propagated_risk_level(
        self,
        delta_ids: List[str],
        report: SemanticDriftReport,
        depth: int,
        edge: RiskEdge,
    ) -> str:
        """Compute propagated risk level with depth decay and edge amplification."""
        levels = [self._delta_risk_level(did, report) for did in delta_ids]
        base = self._max_risk_level(levels)
        order = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        base_score = order.get(base, 0)

        # Depth decay: each level reduces by 1 (bounded at INFO)
        decay = depth
        if edge.carries_auth:
            decay -= self.auth_multiplier
        if edge.carries_state:
            decay -= self.state_multiplier
        effective_score = max(base_score - max(decay, 0), 1)

        reverse_order = {v: k for k, v in order.items()}
        return reverse_order.get(effective_score, "INFO")

    def _propagation_frontier(
        self,
        risk_nodes: Dict[str, RiskNode],
        risk_edges: List[RiskEdge],
        depth: int,
    ) -> List[Tuple[str, List[str], RiskEdge]]:
        """Find nodes at given propagation depth reachable from already-at-risk nodes."""
        frontier: List[Tuple[str, List[str], RiskEdge]] = []
        # Collect nodes that are at risk at the previous depth level
        prev_risk_nodes = {
            nid for nid, n in risk_nodes.items() if n.risk_level != "NONE" and n.propagation_depth < depth
        }
        for edge in risk_edges:
            if edge.upstream in prev_risk_nodes and edge.downstream not in prev_risk_nodes:
                upstream_node = risk_nodes[edge.upstream]
                deltas = upstream_node.direct_deltas + upstream_node.propagated_deltas
                frontier.append((edge.downstream, deltas, edge))
        return frontier
