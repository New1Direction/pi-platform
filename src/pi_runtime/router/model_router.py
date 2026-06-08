"""
Model Router — deterministic routing based on real Agent Registry + Ollama.

Rules (no LLM decisions):
- SIMPLE tasks → LOCAL_LIGHT model (Ollama)
- MODERATE tasks → LOCAL_MEDIUM model (Ollama)
- COMPLEX tasks → BIG_REASONING model (Grok)

This router never hallucinates routing decisions. It only reads the authoritative registry.
"""

from ..registry.agent_registry import get_agent_config, get_model_name, should_use_local_model

ModelName = str  # Now supports real Ollama names + grok-4


def route_agent(agent_id: str) -> str:
    """
    Return the actual model name this agent should use.

    This is the single function that decides local vs big model.
    All decisions are deterministic and based on the registry.
    """
    return get_model_name(agent_id)


def is_local_route(agent_id: str) -> bool:
    """Convenience wrapper — returns True if this agent should stay local (Ollama)."""
    return should_use_local_model(agent_id)


def get_routing_decision(agent_id: str) -> dict:
    """Full routing metadata for observability and dashboard."""
    config = get_agent_config(agent_id)
    model = route_agent(agent_id)
    return {
        "agent_id": agent_id,
        "assigned_model": model,
        "complexity": config.complexity.value,
        "max_tokens": config.max_tokens_per_task,
        "uses_local": is_local_route(agent_id),
        "provider": "ollama" if is_local_route(agent_id) else "xai",
    }
