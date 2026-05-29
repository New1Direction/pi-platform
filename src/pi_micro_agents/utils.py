"""Shared utilities for PI Micro Agents.

Centralizes common helpers that were previously duplicated across every
micro-agent module — notably ``is_strict_mode()``, which existed as a
near-identical copy in all 40+ agent files.
"""

from __future__ import annotations

import json
import os


def is_strict_mode(env_var: str) -> bool:
    """Return True if the named strict-mode flag is enabled.

    Resolution order (first match wins):
    1. Environment variable ``env_var`` (e.g. ``PI_GAS_STRICT_MODE``).
    2. ``~/.antigravitycli/config.json`` key matching ``env_var``.
    3. Project-local ``.antigravitycli/config.json`` (two dirs above this file).
    4. Default: ``True`` (fail-safe — strict by default).

    Args:
        env_var: The environment variable / config key to check, e.g.
                 ``"PI_GAS_STRICT_MODE"``.

    Returns:
        ``True`` when strict mode is active, ``False`` otherwise.

    Example::

        from pi_micro_agents.utils import is_strict_mode

        if is_strict_mode("PI_GAS_STRICT_MODE"):
            status = "REJECTED_GAS_RISK"
    """
    env_val = os.getenv(env_var)
    if env_val is not None:
        return env_val.lower() == "true"

    # Try user-level config, then project-level config
    config_paths = [
        os.path.expanduser("~/.antigravitycli/config.json"),
        os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json"),
    ]
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    data = json.load(f)
                    return bool(data.get(env_var, True))
            except Exception:  # noqa: BLE001 — best-effort config read
                pass

    # Fail-safe: strict mode on by default
    return True
