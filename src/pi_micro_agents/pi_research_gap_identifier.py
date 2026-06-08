"""
PiResearchGapIdentifier

Scans a Deep-Research node for missing cross-references to existing graph nodes.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import GraphNode


class ResearchGapInput(BaseModel):
    node: GraphNode
    existing_node_ids: List[str] = Field(default_factory=list)


class ResearchGapOutput(BaseModel):
    gaps_found: List[str] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)
    agent: str = "PiResearchGapIdentifier"


class PiResearchGapIdentifier:
    """Identifies missing links from a Deep Research stub to the rest of the graph."""

    def __init__(self):
        self.agent_name = "PiResearchGapIdentifier"

    def identify_gaps(self, input_data: ResearchGapInput) -> ResearchGapOutput:
        gaps = []
        suggestions = []

        content_lower = input_data.node.content.lower() + input_data.node.title.lower()

        for node_id in input_data.existing_node_ids:
            if node_id.lower().replace("-", " ") in content_lower:
                continue
            if any(keyword in content_lower for keyword in ["protocol", "binary", "gemini", "prompt"]):
                suggestions.append(f"Consider linking to {node_id}")

        if not input_data.existing_node_ids:
            gaps.append("No existing nodes provided for cross-reference check")

        return ResearchGapOutput(gaps_found=gaps, suggestions=suggestions, agent=self.agent_name)
