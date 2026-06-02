"""The last real per-agent is_strict_mode() resolvers delegate to the central one.

Commit 986d17c centralized ~205 resolvers onto pi_micro_agents.strict_mode.
resolve_strict_mode but explicitly deferred the outliers. Of the remaining real
(importable) outliers, six still resolved strict mode inline AND read
~/.antigravitycli directly — the last copies of the scattered-config footgun.
This pins that they now (a) delegate to the central resolver, (b) pass the right
env key, (c) preserve env-var behavior, and (d) no longer read the config path
themselves.

(The other ~19 "outliers" are dead, unparseable string-literal blob files that
do not import or ship — out of scope here; a separate dead-file cleanup.)
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

# real modules whose module-level is_strict_mode() is consolidated
CONSOLIDATED = {
    "pi_micro_agents.orchestrator.core": "PI_ORCHESTRATOR_STRICT_MODE",
    "pi_micro_agents.pi_cot_shadow": "PI_COT_STRICT_MODE",
    "pi_micro_agents.pi_prompt_shield": "PI_SHIELD_STRICT_MODE",
    "pi_micro_agents.pi_schema_ghost": "PI_GHOST_STRICT_MODE",
    "pi_micro_agents.pi_surplus_orchestrator": "PI_SURPLUS_STRICT_MODE",
}

# files (relative to src/pi_micro_agents) that must no longer read the config path
NO_CONFIG_FILES = [
    "orchestrator/core.py",
    "pi_cot_shadow.py",
    "pi_prompt_shield.py",
    "pi_schema_ghost.py",
    "pi_surplus_orchestrator.py",
    "utils.py",
]


@pytest.mark.parametrize("modname,env_key", list(CONSOLIDATED.items()))
def test_module_delegates_to_central_resolver(monkeypatch, modname, env_key):
    mod = importlib.import_module(modname)
    seen = {}

    def fake(key, default=True):
        seen["key"] = key
        return False

    monkeypatch.setattr(mod, "resolve_strict_mode", fake)
    assert mod.is_strict_mode() is False  # honors the central resolver
    assert seen["key"] == env_key


def test_utils_parameterized_delegates(monkeypatch):
    from pi_micro_agents import utils

    seen = {}

    def fake(key, default=True):
        seen["key"] = key
        return False

    monkeypatch.setattr(utils, "resolve_strict_mode", fake)
    assert utils.is_strict_mode("PI_GAS_STRICT_MODE") is False
    assert seen["key"] == "PI_GAS_STRICT_MODE"


@pytest.mark.parametrize("modname,env_key", list(CONSOLIDATED.items()))
def test_env_var_still_honored(monkeypatch, modname, env_key):
    mod = importlib.import_module(modname)
    monkeypatch.setenv(env_key, "false")
    assert mod.is_strict_mode() is False
    monkeypatch.setenv(env_key, "true")
    assert mod.is_strict_mode() is True


def test_consolidated_files_no_longer_read_config_path():
    base = Path(importlib.import_module("pi_micro_agents").__file__).parent
    for rel in NO_CONFIG_FILES:
        text = (base / rel).read_text(encoding="utf-8")
        assert "antigravitycli" not in text, f"{rel} still reads ~/.antigravitycli directly"
