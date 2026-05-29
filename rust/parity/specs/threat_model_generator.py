"""Parity spec for PiThreatModelGenerator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

PARITY CAVEAT: the original Python agent computes
  ``STRIDE_categories = list(set(categories))``
whose ordering is governed by CPython per-process hash randomization
(``PYTHONHASHSEED``). The Python output ordering of ``STRIDE_categories`` is
therefore NON-DETERMINISTIC across runs whenever more than one category is
present, and cannot be byte-matched by any deterministic Rust port. The Rust
port deduplicates preserving first-seen insertion order. Samples that populate
two or more categories may flake on the ``STRIDE_categories`` field. See the
agent's `deviations`.
"""
from _util import load_py_agent

RUST_NAME = "PiThreatModelGenerator"

_mod = load_py_agent("pi_threat_model_generator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiThreatModelGenerator()
    out = agent.generate_threat_model(_mod.SystemInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean / passing input — no trigger tokens, no categories (deterministic)
    {"input": {"system_desc": "a benign internal batch tool with no external surface"}},
    # database path only -> Information Disclosure + Tampering, risk 60
    {"input": {"system_desc": "service backed by a postgres database and object storage"}},
    # api path only -> Elevation of Privilege + Denial of Service, risk 80
    {"input": {"system_desc": "an api gateway exposing a public endpoint"}},
    # public web path only -> Spoofing, risk 50 (single category, deterministic)
    {"input": {"system_desc": "a public web frontend served to every client"}},
    # all three paths -> 5 threats, max risk 80, multi-category (ORDER MAY FLAKE)
    {"input": {"system_desc": "a system with a database, an api gateway, and a public web frontend"}},
    # short trigger token 'db' substring match -> database path
    {"input": {"system_desc": "uses a small embedded db for caching"}},
    # empty edge input
    {"input": {"system_desc": ""}},
    # non-strict env -> is_secure stays True, status becomes WARN_THREATS
    {"input": {"system_desc": "a public web frontend served to every client"},
     "env": {"PI_SYSTEM_STRICT_MODE": "false"}},
    # strict env explicitly true -> is_secure False
    {"input": {"system_desc": "a public web frontend served to every client"},
     "env": {"PI_SYSTEM_STRICT_MODE": "true"}},
]

# The original agent dedupes via `list(set(categories))` (source line 62), whose
# iteration order is non-deterministic in CPython (per-process hash randomization).
# The Rust port is deterministic; there is no canonical Python order to match, so
# we compare this field as an order-insensitive set.
NORMALIZE = ["STRIDE_categories"]
