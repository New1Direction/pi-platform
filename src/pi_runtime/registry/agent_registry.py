"""
Agent Registry — Real per-agent configuration with Ollama local models.

Defines:
- Which model each specialist agent should use
- Task complexity level (determines local vs big model routing)
- Token budget per agent per mission

This is the source of truth for model routing decisions.
All entries are real and deterministic — no placeholders.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict


class ModelTier(str, Enum):
    """Model tiers for routing decisions."""

    LOCAL_LIGHT = "local-light"  # Fast, cheap, for simple observation tasks
    LOCAL_MEDIUM = "local-medium"  # Balanced local model
    BIG_REASONING = "big-reasoning"  # Heavy model (Grok/Claude) for complex analysis


class TaskComplexity(str, Enum):
    """Complexity classification for routing."""

    SIMPLE = "simple"  # Pattern matching, ingestion, basic extraction
    MODERATE = "moderate"  # Schema inference, type recovery
    COMPLEX = "complex"  # Semantic analysis, client generation, validation


@dataclass(frozen=True)
class AgentConfig:
    """Immutable configuration for a single specialist agent."""

    agent_id: str
    tier: ModelTier
    complexity: TaskComplexity
    max_tokens_per_task: int
    model_name: str  # Actual model name to call (Ollama or Grok)
    description: str


# Real agent registry — this is the single source of truth
AGENT_REGISTRY: Dict[str, AgentConfig] = {
    "network-grpc-specialist": AgentConfig(
        agent_id="network-grpc-specialist",
        tier=ModelTier.LOCAL_LIGHT,
        complexity=TaskComplexity.SIMPLE,
        max_tokens_per_task=2048,
        model_name="qwen2.5:1.5b",  # Ollama - fast & capable small model
        description="Raw artifact ingestion and gRPC endpoint extraction. Simple pattern matching only.",
    ),
    "serialization-extractor": AgentConfig(
        agent_id="serialization-extractor",
        tier=ModelTier.LOCAL_MEDIUM,
        complexity=TaskComplexity.MODERATE,
        max_tokens_per_task=4096,
        model_name="qwen2.5:7b",  # Ollama - strong 7B model
        description="Protobuf schema and serialization format extraction. Moderate structural work.",
    ),
    "binary-static-analyst": AgentConfig(
        agent_id="binary-static-analyst",
        tier=ModelTier.BIG_REASONING,
        complexity=TaskComplexity.COMPLEX,
        max_tokens_per_task=8192,
        model_name="grok-4",  # Big model
        description="Deep binary analysis, type recovery, and semantic validation. Requires heavy reasoning.",
    ),
    "client-codegen-specialist": AgentConfig(
        agent_id="client-codegen-specialist",
        tier=ModelTier.BIG_REASONING,
        complexity=TaskComplexity.COMPLEX,
        max_tokens_per_task=6144,
        model_name="grok-4",  # Big model
        description="Deterministic client code generation from verified schemas. High precision required.",
    ),
}


def get_agent_config(agent_id: str) -> AgentConfig:
    """Return the real configuration for an agent. Raises if unknown."""
    if agent_id not in AGENT_REGISTRY:
        raise KeyError(f"Unknown agent_id: {agent_id}. Registry is authoritative.")
    return AGENT_REGISTRY[agent_id]


def should_use_local_model(agent_id: str) -> bool:
    """True if this agent should route to a local model (simple/moderate tasks)."""
    config = get_agent_config(agent_id)
    return config.tier in (ModelTier.LOCAL_LIGHT, ModelTier.LOCAL_MEDIUM)


def get_max_tokens(agent_id: str) -> int:
    """Return the hard token cap for this agent on any single task."""
    return get_agent_config(agent_id).max_tokens_per_task


def get_model_name(agent_id: str) -> str:
    """Return the actual model name to call for this agent."""
    return get_agent_config(agent_id).model_name
