"""
PiGraphConsistencyChecker

A micro-agent that validates consistency of the typed KnowledgeGraph:
- Checks for dangling edges
- Validates node/edge metadata
- Scores overall graph health

Designed to be called during or after ingest pipeline runs.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List

from pydantic import BaseModel, Field

from src.pi_ide_re.ingest import KnowledgeGraph

if TYPE_CHECKING:
    from src.pi_ide_re.graph_schema import GraphEdge, GraphNode


def is_strict_mode() -> bool:
    os.getenv("PI_GRAPH_STRICT_MODE") if "os" in globals() else None
    # Simplified for this agent
    return True


class GraphConsistencyInput(BaseModel):
    graph_path: str = Field(..., description="Path to knowledge_graph.json")
    check_level: str = Field(default="STRICT", description="STRICT or MEDIUM")


class GraphConsistencyOutput(BaseModel):
    is_consistent: bool
    health_score: float = Field(..., description="0.0 - 100.0")
    issues: List[str] = Field(default_factory=list)
    pi_agents_applied: List[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PiGraphConsistencyChecker:
    """Validates the typed KnowledgeGraph for consistency (supports both batch and single-node modes)."""

    def __init__(self) -> None:
        self.agent_name = "PiGraphConsistencyChecker"

    def run(self, node_id: str, node: GraphNode, edges: List[GraphEdge] = None) -> dict:
        """Convenience method for the ingest pipeline (single node focus)."""
        issues = []
        confidence = 0.95

        if not node.metadata.source_page:
            issues.append("Missing source_page in metadata")
            confidence -= 0.15

        # Check if this node has dangling references in the provided edges
        if edges:
            connected = {e.source for e in edges} | {e.target for e in edges}
            if node_id not in connected:
                issues.append("Node has no connected edges in current batch")

        result = {
            "is_consistent": len(issues) == 0,
            "confidence_score": max(0.5, round(confidence, 2)),
            "issues": issues,
            "agent": self.agent_name,
        }
        return result

    def check_graph(self, input_envelope: GraphConsistencyInput) -> GraphConsistencyOutput:
        """Full graph validation (batch mode)."""
        issues: List[str] = []
        health = 100.0

        try:
            with open(input_envelope.graph_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            graph = KnowledgeGraph.model_validate(data)
        except Exception as e:
            return GraphConsistencyOutput(
                is_consistent=False,
                health_score=0.0,
                issues=[f"Failed to load graph: {str(e)}"],
                pi_agents_applied=[self.agent_name],
            )

        node_ids = set(graph.nodes.keys())
        for edge in graph.edges:
            if edge.source not in node_ids:
                issues.append(f"Dangling source: {edge.source}")
                health -= 8
            if edge.target not in node_ids:
                issues.append(f"Dangling target: {edge.target}")
                health -= 8

        for node_id, node in graph.nodes.items():
            if not node.metadata.source_page:
                issues.append(f"Missing source_page on node {node_id}")
                health -= 3

        is_consistent = len(issues) == 0
        final_health = max(0.0, min(100.0, health))

        return GraphConsistencyOutput(
            is_consistent=is_consistent,
            health_score=round(final_health, 1),
            issues=issues,
            pi_agents_applied=[self.agent_name],
        )
