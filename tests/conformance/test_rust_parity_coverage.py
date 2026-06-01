"""Every Rust-registered agent must have a parity spec (coverage gate).

The Rust core is sold as "byte-for-byte equivalent to Python". The existing
rust/parity check only verifies specs ⊆ registry (every spec maps to a real
agent). This adds the missing direction — registry ⊆ specs — so a Rust agent can
never be added without a parity spec, which would otherwise silently run
unverified-against-Python. Pure-Python (parses sources), so it runs in the main
CI without building the cdylib.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_REGISTRY = _REPO / "rust" / "crates" / "pi-agents" / "src" / "registry.rs"
_SPEC_DIR = _REPO / "rust" / "parity" / "specs"


def _registered_agents() -> set:
    text = _REGISTRY.read_text(encoding="utf-8")
    return set(re.findall(r'm\.insert\(\s*"([^"]+)"', text))


def _spec_rust_names() -> set:
    names = set()
    for fp in _SPEC_DIR.glob("*.py"):
        if fp.name.startswith("_"):
            continue
        m = re.search(r'RUST_NAME\s*=\s*"([^"]+)"', fp.read_text(encoding="utf-8"))
        if m:
            names.add(m.group(1))
    return names


def test_every_registered_rust_agent_has_a_parity_spec():
    registered = _registered_agents()
    specs = _spec_rust_names()
    # Guard against a vacuous pass (e.g. a parse regression returning empty sets).
    assert len(registered) >= 200, f"registry parse looks wrong: only {len(registered)} agents"
    assert len(specs) >= 200, f"spec parse looks wrong: only {len(specs)} specs"
    missing = registered - specs
    assert not missing, f"Rust agents registered but with NO parity spec (add one): {sorted(missing)}"
