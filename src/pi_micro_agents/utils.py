"""Shared utilities for PI Micro Agents.

Centralizes common helpers that were previously duplicated across every
micro-agent module — notably ``is_strict_mode()``, which existed as a
near-identical copy in all 40+ agent files.
"""

from __future__ import annotations

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode(env_var: str) -> bool:
    """Return True if the named strict-mode flag is enabled.

    Thin compatibility wrapper that delegates to the single source of truth,
    :func:`pi_micro_agents.strict_mode.resolve_strict_mode` (see it for the exact
    resolution order; the default is fail-safe ``True``).

    Args:
        env_var: The environment variable / config key to check, e.g.
                 ``"PI_GAS_STRICT_MODE"``.

    Returns:
        ``True`` when strict mode is active, ``False`` otherwise.
    """
    return resolve_strict_mode(env_var)
