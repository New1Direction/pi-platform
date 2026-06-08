"""
PiDeepResearchPromoter

Evaluates whether a Deep Research node is ready to be promoted to a full page.
"""

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import GraphNode


class PromoteInput(BaseModel):
    node: GraphNode


class PromoteOutput(BaseModel):
    should_promote: bool
    score: float
    reasons: List[str] = Field(default_factory=list)
    agent: str = "PiDeepResearchPromoter"


class PiDeepResearchPromoter:
    def __init__(self):
        self.agent_name = "PiDeepResearchPromoter"

    def evaluate(self, input_data: PromoteInput) -> PromoteOutput:
        node = input_data.node
        score = 0.0
        reasons = []

        if len(node.metadata.pi_agents_applied) >= 2:
            score += 0.3
            reasons.append("Multiple agents have touched this node")

        if node.metadata.priority_score >= 0.8:
            score += 0.4
            reasons.append("High priority score")

        if "findings" in node.content.lower() or len(node.content) > 400:
            score += 0.3
            reasons.append("Substantial content present")

        should_promote = score >= 0.7

        return PromoteOutput(
            should_promote=should_promote, score=round(score, 2), reasons=reasons, agent=self.agent_name
        )
