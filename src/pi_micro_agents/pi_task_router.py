"""
PiTaskRouter

System-centric orchestration agent.
Given a node/event, decides which specialist agents should run and in what order.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import GraphNode


class TaskRouterInput(BaseModel):
    node: GraphNode
    available_agents: List[str] = Field(default_factory=list)
    context: str = ""  # e.g. "new stub", "after enrichment", "health check"


class TaskRouterOutput(BaseModel):
    recommended_sequence: List[str]
    reasoning: str
    agent: str = "PiTaskRouter"


class PiTaskRouter:
    """
    Decides the optimal sequence of specialist agents for a given node.
    This is the first true 'conductor' agent.
    """

    def __init__(self):
        self.agent_name = "PiTaskRouter"

        # Simple rule-based routing table (will later be LLM-augmented)
        self.routing_rules = {
            "deep-research": {
                "new": [
                    "PiResearchGapIdentifier",
                    "PiStubEnricherAgent",
                    "PiNodePrioritizer",
                    "PiGraphConsistencyChecker",
                    "PiDeepResearchPromoter",
                ],
                "after_enrichment": ["PiNodePrioritizer", "PiDeepResearchPromoter"],
                "health_check": ["PiGraphConsistencyChecker", "PiGraphHealthReporter"],
            },
            "entity": {
                "new": ["PiGraphConsistencyChecker", "PiGraphHealthReporter"],
                "update": ["PiGraphDeltaAuditor"],
            },
        }

    def route(self, input_data: TaskRouterInput) -> TaskRouterOutput:
        node_type = input_data.node.type
        context = input_data.context.lower() if input_data.context else "new"

        sequence = []

        if node_type in self.routing_rules:
            rules = self.routing_rules[node_type]
            if context in rules:
                sequence = rules[context]
            elif "new" in rules:
                sequence = rules["new"]

        # Filter to only agents that are actually available
        if input_data.available_agents:
            sequence = [a for a in sequence if a in input_data.available_agents]

        reasoning = (
            f"Selected sequence based on node type '{node_type}' and context '{context}' using deterministic rules."
        )

        return TaskRouterOutput(recommended_sequence=sequence, reasoning=reasoning, agent=self.agent_name)
