"""
PiStubEnricherAgent

Applies deterministic enrichment rules to Deep Research stubs.
"""

from typing import List

from pydantic import BaseModel, Field

from src.pi_ide_re.graph_schema import GraphNode


class StubEnrichInput(BaseModel):
    node: GraphNode


class StubEnrichOutput(BaseModel):
    enriched_tags: List[str] = Field(default_factory=list)
    suggested_agents: List[str] = Field(default_factory=list)
    agent: str = "PiStubEnricherAgent"


class PiStubEnricherAgent:
    """Deterministically enriches Deep Research stubs with tags and agent suggestions."""

    def __init__(self):
        self.agent_name = "PiStubEnricherAgent"

    def enrich(self, input_data: StubEnrichInput) -> StubEnrichOutput:
        tags = list(input_data.node.metadata.tags)
        suggested = []

        title_lower = input_data.node.title.lower()

        if "protocol" in title_lower:
            tags.append("protocol-analysis")
            suggested.append("PiGrpcProtocolInterceptor")
        if "binary" in title_lower or "secret" in title_lower:
            tags.append("binary-analysis")
            suggested.append("PiHardcodedSecretDetector")
            suggested.append("PiMagicNumberScanner")
        if "prompt" in title_lower or "llm" in title_lower:
            tags.append("llm-surface")
            suggested.append("PiLLMBase64EncodingDeobfuscator")

        return StubEnrichOutput(enriched_tags=list(set(tags)), suggested_agents=suggested, agent=self.agent_name)
