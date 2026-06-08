"""
PiGraphQueryEngine

Simple query interface over the typed KnowledgeGraph.
Supports basic searches by type, tag, title, and neighbor lookup.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import KnowledgeGraph


class GraphQueryInput(BaseModel):
    graph: KnowledgeGraph
    query_type: str = Field(..., description="nodes_by_type | nodes_by_tag | search | neighbors | open_deep_research")
    query_value: Optional[str] = None
    node_id: Optional[str] = None
    limit: int = 20


class GraphQueryOutput(BaseModel):
    results: List[dict] = Field(default_factory=list)
    count: int = 0
    agent: str = "PiGraphQueryEngine"


class PiGraphQueryEngine:
    """Lightweight query engine for the KnowledgeGraph."""

    def __init__(self):
        self.agent_name = "PiGraphQueryEngine"

    def query(self, input_data: GraphQueryInput) -> GraphQueryOutput:
        kg = input_data.graph
        qtype = input_data.query_type.lower()
        results = []

        if qtype == "nodes_by_type":
            for nid, node in kg.nodes.items():
                if node.type == input_data.query_value:
                    results.append(
                        {
                            "id": nid,
                            "title": node.title,
                            "type": node.type,
                            "priority": node.metadata.priority_score,
                            "agents": node.metadata.pi_agents_applied,
                        }
                    )

        elif qtype == "nodes_by_tag":
            for nid, node in kg.nodes.items():
                if input_data.query_value in node.metadata.tags:
                    results.append(
                        {"id": nid, "title": node.title, "type": node.type, "priority": node.metadata.priority_score}
                    )

        elif qtype == "search":
            qv = (input_data.query_value or "").lower()
            for nid, node in kg.nodes.items():
                if qv in node.title.lower() or qv in node.content.lower():
                    results.append(
                        {"id": nid, "title": node.title, "type": node.type, "priority": node.metadata.priority_score}
                    )

        elif qtype == "neighbors":
            if not input_data.node_id:
                return GraphQueryOutput(results=[], count=0, agent=self.agent_name)

            neighbors = []
            for edge in kg.edges:
                if edge.source == input_data.node_id:
                    neighbors.append({"direction": "out", "target": edge.target, "type": edge.metadata.relation_type})
                elif edge.target == input_data.node_id:
                    neighbors.append({"direction": "in", "source": edge.source, "type": edge.metadata.relation_type})
            results = neighbors

        elif qtype == "open_deep_research":
            for nid, node in kg.nodes.items():
                if node.type == "deep-research" and "promotion-ready" not in node.metadata.tags:
                    results.append(
                        {
                            "id": nid,
                            "title": node.title,
                            "priority": node.metadata.priority_score,
                            "agents": node.metadata.pi_agents_applied,
                        }
                    )

        results = results[: input_data.limit]
        return GraphQueryOutput(results=results, count=len(results), agent=self.agent_name)
