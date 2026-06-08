"""
PiGraphDeltaAuditor

Compares two KnowledgeGraph snapshots and reports changes.
"""

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import KnowledgeGraph


class GraphDeltaInput(BaseModel):
    before: KnowledgeGraph
    after: KnowledgeGraph


class GraphDeltaOutput(BaseModel):
    added_nodes: List[str] = Field(default_factory=list)
    removed_nodes: List[str] = Field(default_factory=list)
    added_edges: int = 0
    removed_edges: int = 0
    agent: str = "PiGraphDeltaAuditor"


class PiGraphDeltaAuditor:
    def __init__(self):
        self.agent_name = "PiGraphDeltaAuditor"

    def compute_delta(self, input_data: GraphDeltaInput) -> GraphDeltaOutput:
        before_nodes = set(input_data.before.nodes.keys())
        after_nodes = set(input_data.after.nodes.keys())

        return GraphDeltaOutput(
            added_nodes=list(after_nodes - before_nodes),
            removed_nodes=list(before_nodes - after_nodes),
            added_edges=len(input_data.after.edges) - len(input_data.before.edges),
            removed_edges=0,  # simplified
            agent=self.agent_name,
        )
