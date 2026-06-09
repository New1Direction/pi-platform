"""Generic agent dispatch: every registered agent must be executable.

The consensus dispatcher hand-mapped ~96 agents to their bespoke entry method via
an if/elif on agent_name; the other 152 registered agents had no branch and threw
"Unknown agent" (61% of the registry was dead). The generic fallback resolves an
agent's single public entry method and calls it. This pins that NO registered
agent can fall through to the "Unknown agent" raise.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from pi_micro_agents.orchestrator.consensus import resolve_entry_method
from pi_micro_agents.orchestrator.router import AgentRouter

_CONSENSUS_SRC = (
    pathlib.Path(__file__).resolve().parents[3] / "src/pi_micro_agents/orchestrator/consensus.py"
).read_text()
_EXPLICIT = set(re.findall(r'agent_name\s*==\s*"([^"]+)"', _CONSENSUS_SRC))


def test_every_registered_agent_is_dispatchable():
    """No registered agent may be both un-branched AND un-resolvable."""
    dead = []
    for r in AgentRouter.routes:
        if r.agent_name in _EXPLICIT:
            continue  # has a hand-written dispatch branch
        if resolve_entry_method(r.agent_class()) is None:
            dead.append(r.agent_name)
    assert not dead, f"{len(dead)} agents would raise 'Unknown agent': {dead[:10]}"


@pytest.mark.parametrize(
    "agent_name, expected_method",
    [
        ("PiUniswapV3PoolSentry", "audit_uniswap_v3"),
        ("PiSolidityCompilerBugsSentry", "audit_compiler_bugs"),
        ("PiPromptLeakBuster", "scan_text"),
    ],
)
def test_resolver_finds_the_entry_method(agent_name, expected_method):
    route = next(r for r in AgentRouter.routes if r.agent_name == agent_name)
    assert resolve_entry_method(route.agent_class()) == expected_method


def test_ambiguous_agent_resolved_via_verb_tiebreak():
    # has both audit_entropy_leaks (entry) and calculate_shannon_entropy (helper)
    route = next(r for r in AgentRouter.routes if r.agent_name == "PiGitSecretEntropyLeakSentry")
    assert resolve_entry_method(route.agent_class()) == "audit_entropy_leaks"
