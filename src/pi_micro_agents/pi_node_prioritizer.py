"""
PiNodePrioritizer

Re-ranks priority_score using impact × urgency × connectivity (deterministic).
"""

from pydantic import BaseModel

from src.pi_ide_re.graph_schema import GraphNode


class NodePrioritizeInput(BaseModel):
    node: GraphNode
    connectivity_score: float = 0.5  # number of connected edges / total nodes


class NodePrioritizeOutput(BaseModel):
    new_priority_score: float
    reasoning: str
    agent: str = "PiNodePrioritizer"


class PiNodePrioritizer:
    """Deterministic priority scoring for graph nodes."""

    def __init__(self):
        self.agent_name = "PiNodePrioritizer"

    def prioritize(self, input_data: NodePrioritizeInput) -> NodePrioritizeOutput:
        base = input_data.node.metadata.priority_score or 0.6
        connectivity = min(1.0, input_data.connectivity_score)

        # Simple formula: impact (base) * urgency (assume high for deep-research) * connectivity
        urgency = 0.9 if input_data.node.type == "deep-research" else 0.6
        new_score = round(min(1.0, base * urgency * (0.5 + 0.5 * connectivity)), 2)

        return NodePrioritizeOutput(
            new_priority_score=new_score,
            reasoning=f"Base {base} × Urgency {urgency} × Connectivity {connectivity}",
            agent=self.agent_name,
        )
