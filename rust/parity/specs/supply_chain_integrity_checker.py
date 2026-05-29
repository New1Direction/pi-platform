"""Parity spec for PiSupplyChainIntegrityChecker.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSupplyChainIntegrityChecker"

_mod = load_py_agent("pi_supply_chain_integrity_checker.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSupplyChainIntegrityChecker()
    out = agent.check_supply_chain(_mod.SupplyChainInput(**data))
    return out.model_dump()


_CLEAN = "requests==2.31.0\nlodash@4.17.21\nflask-cors==4.0.0\n"
_TYPO_REQEUSTS = "reqeusts==2.31.0\nnumpy==1.26.0\n"
_TYPO_BOTO4 = "boto4>=1.0.0\n"
_TYPO_MULTI = "boto4\nloadsh\npyton\nflask-corss\nreqeusts\n"
_INSECURE_SOURCE = "mydep @ http://internal.example.com/team/repo.git\n"
_TYPO_AND_INSECURE = "loadsh @ http://hub.example.com/x.git\n"
# upper-case input exercises the .lower() normalization in the agent
_TYPO_UPPER = "REQEUSTS==2.31.0\n"

SAMPLES = [
    # clean / passing manifest
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _CLEAN}},
    # single typosquat -> risk 90 -> rejected under strict default
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _TYPO_REQEUSTS}},
    # different typosquat path
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _TYPO_BOTO4}},
    # all five typosquats in insertion order
    {"input": {"manifest_path": "package.json", "manifest_content": _TYPO_MULTI}},
    # insecure http:// + .git source -> risk 75
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _INSECURE_SOURCE}},
    # both typosquat and insecure source -> max risk 90
    {"input": {"manifest_path": "package.json", "manifest_content": _TYPO_AND_INSECURE}},
    # case normalization (.lower())
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _TYPO_UPPER}},
    # empty / edge manifest
    {"input": {"manifest_path": "empty.txt", "manifest_content": ""}},
    # non-strict env -> WARN path, is_secure stays True even with risk
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _TYPO_REQEUSTS},
     "env": {"PI_SUPPLY_CHAIN_STRICT_MODE": "false"}},
    # explicit strict env -> rejected
    {"input": {"manifest_path": "requirements.txt", "manifest_content": _TYPO_REQEUSTS},
     "env": {"PI_SUPPLY_CHAIN_STRICT_MODE": "true"}},
]
