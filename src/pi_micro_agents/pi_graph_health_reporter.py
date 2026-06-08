"""
PiGraphHealthReporter

Lightweight health check of the entire KnowledgeGraph.
"""

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import KnowledgeGraph


class HealthReportInput(BaseModel):
    graph: KnowledgeGraph


class HealthReportOutput(BaseModel):
    health_score: float
    orphan_nodes: List[str] = Field(default_factory=list)
    stale_nodes: int = 0
    summary: str
    agent: str = "PiGraphHealthReporter"


class PiGraphHealthReporter:
    def __init__(self):
        self.agent_name = "PiGraphHealthReporter"

    def report(self, input_data: HealthReportInput) -> HealthReportOutput:
        graph = input_data.graph
        orphans = []
        connected = set()

        for edge in graph.edges:
            connected.add(edge.source)
            connected.add(edge.target)

        for node_id in graph.nodes:
            if node_id not in connected:
                orphans.append(node_id)

        score = max(30.0, 100.0 - (len(orphans) * 12))

        return HealthReportOutput(
            health_score=round(score, 1),
            orphan_nodes=orphans,
            stale_nodes=0,
            summary=f"{len(orphans)} orphan nodes. Overall health: {round(score)}/100",
            agent=self.agent_name,
        )
