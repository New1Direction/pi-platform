"""Centralized strict-mode resolution for PI micro-agents.

Single source of truth for resolving an agent's strict-mode toggle, replacing the
~200 near-identical ``is_strict_mode()`` copies that each independently reached for
a user-home config file.

Resolution order for a given ``env_key`` (e.g. ``"PI_REENTRANCY_STRICT_MODE"``):

1. explicit environment variable (``"true"``/``"false"``), if set;
2. ``~/.antigravitycli/config.json`` (per-user), if present;
3. repo-local ``.antigravitycli/config.json``, if present;
4. **safe default: True (strict / fail-closed).**

The default is ``True`` so that, absent any configuration, a scanner fails CLOSED:
a detected vulnerability is reported as insecure rather than silently downgraded to
an advisory pass. (Findings are always populated regardless of mode; strict vs.
advisory only governs the ``is_secure`` disposition and status label.)
"""

from __future__ import annotations

import json
import os
from typing import Optional

_CONFIG_PATHS = (
    os.path.expanduser("~/.antigravitycli/config.json"),
    os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json"),
)


def resolve_strict_mode(env_key: str, default: bool = True) -> bool:
    """Resolve whether strict (fail-closed) mode is enabled for ``env_key``.

    See the module docstring for the resolution order. ``default`` (True) is the
    fail-closed disposition used when nothing is configured.
    """
    env_val: Optional[str] = os.getenv(env_key)
    if env_val is not None:
        return env_val.lower() == "true"

    for config_path in _CONFIG_PATHS:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    return bool(json.load(f).get(env_key, default))
            except Exception:
                # Unreadable/corrupt config must not silently disable strict mode.
                return default
    return default
