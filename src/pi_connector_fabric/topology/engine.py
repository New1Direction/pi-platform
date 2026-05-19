"""Cross-System Topology Engine.

Semantic relationship engine linking artifacts across different infrastructure
systems. Produces UnifiedTopologyGraph, CrossSystemDependencyGraph, and
RiskPropagationTopology.

Deterministic. No probabilistic graph inference. All links are explicit.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from pi_connector_fabric.sdk.core import NormalizedArtifact


# ──────────────────────────────
#  Topology Primitives
# ──────────────────────────────

@dataclass(frozen=True)
class TopologyNode:
    """A node in the unified topology graph."""

    node_id: str
    node_type: str
    system: str
    tenant_id: str
    artifact_hash: str
    properties: Dict[str, Any] = field(default_factory=dict)
    labels: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TopologyEdge:
    """An edge in the unified topology graph."""

    edge_id: str
    from_node: str
    to_node: str
    relation: str
    system: str
    weight: float = 1.0
    bidirectional: bool = False
    provenance: Tuple[str, ...] = ()


# ──────────────────────────────
#  Unified Topology Graph
# ──────────────────────────────

class UnifiedTopologyGraph:
    """Deterministic cross-system topology graph.

    All nodes and edges are immutable. Graph is constructed from
    NormalizedArtifact instances using explicit linking rules.
    """

    def __init__(self, tenant_id: str, correlation_id: str) -> None:
        self.tenant_id = tenant_id
        self.correlation_id = correlation_id
        self._nodes: Dict[str, TopologyNode] = {}
        self._edges: Dict[str, TopologyEdge] = {}
        self._adjacency: Dict[str, List[str]] = {}

    def add_artifact(self, artifact: NormalizedArtifact) -> List[TopologyNode]:
        """Add a NormalizedArtifact to the topology graph.

        Extracts nodes and edges from artifact payload.
        Returns list of created TopologyNode instances.
        """
        created_nodes: List[TopologyNode] = []
        payload = artifact.payload

        # Extract nodes from artifact payload
        if "nodes" in payload:
            for raw_node in payload["nodes"]:
                node = TopologyNode(
                    node_id=raw_node.get("id", f"node_{len(self._nodes)}"),
                    node_type=raw_node.get("type", "unknown"),
                    system=artifact.source_system,
                    tenant_id=artifact.tenant_id,
                    artifact_hash=artifact.artifact_hash,
                    properties={k: v for k, v in raw_node.items() if k not in ("id", "type")},
                    labels=tuple(raw_node.get("labels", {}).keys()),
                )
                if node.node_id not in self._nodes:
                    self._nodes[node.node_id] = node
                    self._adjacency[node.node_id] = []
                    created_nodes.append(node)

        # Extract edges
        if "edges" in payload:
            for raw_edge in payload["edges"]:
                from_node = raw_edge.get("from", "")
                to_node = raw_edge.get("to", "")
                edge = TopologyEdge(
                    edge_id=f"edge_{from_node}_{to_node}_{raw_edge.get('relation', 'link')}",
                    from_node=from_node,
                    to_node=to_node,
                    relation=raw_edge.get("relation", "link"),
                    system=artifact.source_system,
                    weight=raw_edge.get("weight", 1.0),
                    bidirectional=raw_edge.get("bidirectional", False),
                    provenance=(f"artifact:{artifact.artifact_hash[:16]}",),
                )
                if edge.edge_id not in self._edges:
                    self._edges[edge.edge_id] = edge
                    if from_node in self._adjacency:
                        self._adjacency[from_node].append(to_node)
                    if edge.bidirectional and to_node in self._adjacency:
                        self._adjacency[to_node].append(from_node)

        # Extract identity relationships
        if "relationships" in payload:
            for raw_rel in payload["relationships"]:
                from_node = raw_rel.get("from", "")
                to_node = raw_rel.get("to", "")
                edge = TopologyEdge(
                    edge_id=f"rel_{from_node}_{to_node}_{raw_rel.get('relation', 'rel')}",
                    from_node=from_node,
                    to_node=to_node,
                    relation=raw_rel.get("relation", "rel"),
                    system=artifact.source_system,
                    provenance=(f"artifact:{artifact.artifact_hash[:16]}",),
                )
                if edge.edge_id not in self._edges:
                    self._edges[edge.edge_id] = edge
                    if from_node in self._adjacency:
                        self._adjacency[from_node].append(to_node)

        # Extract dependencies
        if "dependencies" in payload:
            for raw_dep in payload["dependencies"]:
                from_node = raw_dep.get("from", "")
                to_node = raw_dep.get("to", "")
                # Ensure from_node exists in adjacency
                if from_node not in self._adjacency:
                    self._adjacency[from_node] = []
                edge = TopologyEdge(
                    edge_id=f"dep_{from_node}_{to_node}",
                    from_node=from_node,
                    to_node=to_node,
                    relation=raw_dep.get("relation", "depends_on"),
                    system=artifact.source_system,
                    provenance=(f"artifact:{artifact.artifact_hash[:16]}",),
                )
                if edge.edge_id not in self._edges:
                    self._edges[edge.edge_id] = edge
                    self._adjacency[from_node].append(to_node)

        return created_nodes

    def add_cross_system_link(
        self,
        from_node: str,
        to_node: str,
        relation: str,
        provenance: str,
    ) -> TopologyEdge:
        """Add an explicit cross-system link between two topology nodes."""
        edge = TopologyEdge(
            edge_id=f"xsys_{from_node}_{to_node}_{relation}",
            from_node=from_node,
            to_node=to_node,
            relation=relation,
            system="cross_system",
            provenance=(provenance,),
        )
        self._edges[edge.edge_id] = edge
        if from_node in self._adjacency:
            self._adjacency[from_node].append(to_node)
        return edge

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[str]:
        return list(self._adjacency.get(node_id, []))

    def get_nodes(self) -> List[TopologyNode]:
        return list(self._nodes.values())

    def get_edges(self) -> List[TopologyEdge]:
        return list(self._edges.values())

    def graph_hash(self) -> str:
        """Deterministic hash of the entire graph state."""
        canonical = {
            "nodes": sorted([
                {"id": n.node_id, "type": n.node_type, "system": n.system}
                for n in self._nodes.values()
            ], key=lambda x: x["id"]),
            "edges": sorted([
                {"from": e.from_node, "to": e.to_node, "relation": e.relation}
                for e in self._edges.values()
            ], key=lambda x: (x["from"], x["to"], x["relation"])),
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


# ──────────────────────────────
#  Cross-System Dependency Graph
# ──────────────────────────────

class CrossSystemDependencyGraph:
    """Explicit cross-system dependency mapping engine.

    Links artifacts across systems using deterministic matching rules.
    No fuzzy matching. All links are explicit and auditable.
    """

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._links: Dict[str, List[Tuple[str, str, str]]] = {}  # system -> [(from, to, relation)]
        self._artifacts_by_system: Dict[str, Dict[str, NormalizedArtifact]] = {}

    def register_artifact(self, artifact: NormalizedArtifact) -> None:
        """Register an artifact for cross-system linking."""
        system = artifact.source_system
        if system not in self._artifacts_by_system:
            self._artifacts_by_system[system] = {}
        self._artifacts_by_system[system][artifact.artifact_id] = artifact

    def add_link_rule(
        self,
        from_system: str,
        to_system: str,
        from_field: str,
        to_field: str,
        relation: str,
    ) -> None:
        """Add an explicit cross-system link rule.

        When artifacts match on the specified fields, a link is created.
        """
        from_artifacts = self._artifacts_by_system.get(from_system, {})
        to_artifacts = self._artifacts_by_system.get(to_system, {})

        for fa in from_artifacts.values():
            from_val = self._field_value(fa, from_field)
            if not from_val:
                continue
            for ta in to_artifacts.values():
                to_val = self._field_value(ta, to_field)
                if from_val == to_val:
                    key = f"{from_system}->{to_system}"
                    if key not in self._links:
                        self._links[key] = []
                    self._links[key].append((fa.artifact_id, ta.artifact_id, relation))

    def _field_value(self, artifact: NormalizedArtifact, field_path: str) -> Optional[str]:
        """Extract a nested field value from artifact payload."""
        parts = field_path.split(".")
        current: Any = artifact.payload
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                return None
        return str(current) if current is not None else None

    def get_links(self, from_system: str, to_system: str) -> List[Tuple[str, str, str]]:
        return list(self._links.get(f"{from_system}->{to_system}", []))

    def to_topology_edges(self) -> List[TopologyEdge]:
        """Convert all cross-system links to TopologyEdge instances."""
        edges = []
        for key, links in self._links.items():
            for from_id, to_id, relation in links:
                edges.append(TopologyEdge(
                    edge_id=f"xsys_{from_id}_{to_id}_{relation}",
                    from_node=from_id,
                    to_node=to_id,
                    relation=relation,
                    system=key,
                ))
        return edges


# ──────────────────────────────
#  Risk Propagation Topology
# ──────────────────────────────

class RiskPropagationTopology:
    """Deterministic risk propagation analysis over topology graph.

    Computes blast radius from a given node using explicit edge weights.
    No probabilistic scoring. Reachability is deterministic.
    """

    def __init__(self, graph: UnifiedTopologyGraph) -> None:
        self.graph = graph

    def blast_radius(
        self,
        origin_node: str,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """Compute deterministic blast radius from origin node.

        Returns reachable nodes within max_hops via BFS.
        """
        visited: Dict[str, int] = {origin_node: 0}
        queue = [origin_node]
        head = 0

        while head < len(queue):
            current = queue[head]
            head += 1
            current_hops = visited[current]
            if current_hops >= max_hops:
                continue
            for neighbor in self.graph.get_neighbors(current):
                if neighbor not in visited:
                    visited[neighbor] = current_hops + 1
                    queue.append(neighbor)

        return {
            "origin": origin_node,
            "max_hops": max_hops,
            "reachable_count": len(visited) - 1,
            "reachable_nodes": sorted([n for n in visited if n != origin_node]),
            "hop_distribution": {h: sum(1 for v in visited.values() if v == h) for h in range(1, max_hops + 1)},
        }

    def critical_path(
        self,
        from_node: str,
        to_node: str,
    ) -> Optional[List[str]]:
        """Find shortest path between two nodes using BFS."""
        if from_node == to_node:
            return [from_node]

        visited = {from_node: None}
        queue = [from_node]
        head = 0

        while head < len(queue):
            current = queue[head]
            head += 1
            for neighbor in self.graph.get_neighbors(current):
                if neighbor not in visited:
                    visited[neighbor] = current
                    if neighbor == to_node:
                        # Reconstruct path
                        path = [to_node]
                        while path[-1] != from_node:
                            prev = visited[path[-1]]
                            if prev is None:
                                break
                            path.append(prev)
                        return list(reversed(path))
                    queue.append(neighbor)
        return None
