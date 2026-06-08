"""
base.py - shared types for RE pipeline stages.

A stage's deterministic half returns a ``StageResult`` (content-addressed nodes
+ edges + a small summary). Stages never mutate global state; the caller merges
results into a KnowledgeGraph, so a run is reproducible from its artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol

from ..graph_schema import GraphEdge, GraphNode, KnowledgeGraph, save_knowledge_graph


class StageError(RuntimeError):
    """Raised when a live capture cannot run (missing tool, dead target, ...).

    Carries a human-facing remediation hint so the CLI can tell the operator
    exactly which optional dependency to install.
    """


@dataclass
class StageResult:
    stage: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_to(self, graph: KnowledgeGraph) -> None:
        """Merge this result into a graph in memory (no persistence)."""
        for node in self.nodes:
            graph.nodes[node.id] = node
        graph.edges.extend(self.edges)

    def merge_into(self, graph: KnowledgeGraph, vault_path: str = "vault") -> None:
        """Merge into a graph and persist it to disk."""
        self.add_to(graph)
        save_knowledge_graph(graph, vault_path)

    def node_ids(self) -> List[str]:
        return [n.id for n in self.nodes]


class Stage(Protocol):
    """Structural protocol every stage satisfies for its deterministic half."""

    name: str

    def ingest(self, capture: Dict[str, Any]) -> StageResult: ...
