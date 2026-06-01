"""PI Agent Interceptor Package.

Defines the FastAPI interceptor proxy, AST screens, command sanitizers,
and the risk-score human-in-the-loop validation engine.
"""

from __future__ import annotations

from pi_agent_interceptor.proxy import app

__all__ = ["app"]
