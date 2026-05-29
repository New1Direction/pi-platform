"""Parity spec for PiDimensionalAnalysisSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDimensionalAnalysisSentry"

_mod = load_py_agent("pi_dimensional_analysis_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDimensionalAnalysisSentry()
    out = agent.audit_dimensions(_mod.DimensionalAnalysisInput(**data))
    return out.model_dump()


# A clean, dimensionally-consistent assignment: every matched var shares "wei".
_CLEAN = "total = principal + interest"
_CLEAN_REG = {"principal": "wei", "interest": "wei", "total": "wei"}

# Mixed units in a single arithmetic line (wei vs gwei) -> one mismatch.
_MIXED = "fee = base + rate"
_MIXED_REG = {"base": "wei", "rate": "gwei", "fee": "wei"}

# Three-way collision so the loop over matched_vars[1:] emits multiple findings.
_TRIPLE = "out = a * b + c"
_TRIPLE_REG = {"a": "wei", "b": "gwei", "c": "ether"}

# Assignment without any +,-,*,/ operator: must be skipped (no scan).
_NOOP = "x = y"
_NOOP_REG = {"x": "wei", "y": "gwei"}

# Registry keys with regex-special chars (e.g. solidity index access) that must
# survive re.escape and \b word-boundary matching.
_INDEX = "balances[msg.sender] = balances[msg.sender] + rate"
_INDEX_REG = {"balances[msg.sender]": "wei", "rate": "gwei"}

# Multiple lines: mix of clean, skipped, and flagged.
_MULTI = "\n".join(
    [
        "good = amount + bonus",
        "skipped = label",
        "    bad =   left * right  ",
    ]
)
_MULTI_REG = {
    "amount": "wei",
    "bonus": "wei",
    "label": "usd",
    "left": "wei",
    "right": "gwei",
}

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "a.sol", "source_code": _CLEAN, "unit_registry": _CLEAN_REG}},
    # single mixed-unit collision (strict default -> REJECTED)
    {"input": {"file_path": "a.sol", "source_code": _MIXED, "unit_registry": _MIXED_REG}},
    # multiple collisions on one line
    {"input": {"file_path": "a.sol", "source_code": _TRIPLE, "unit_registry": _TRIPLE_REG}},
    # arithmetic-less assignment is skipped
    {"input": {"file_path": "a.sol", "source_code": _NOOP, "unit_registry": _NOOP_REG}},
    # regex-special registry keys (index access) with strip() on the line
    {"input": {"file_path": "a.sol", "source_code": _INDEX, "unit_registry": _INDEX_REG}},
    # multi-line mixed scenario
    {"input": {"file_path": "a.sol", "source_code": _MULTI, "unit_registry": _MULTI_REG}},
    # empty source + empty registry -> trivially secure
    {"input": {"file_path": "a.sol", "source_code": "", "unit_registry": {}}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.sol", "source_code": _MIXED, "unit_registry": _MIXED_REG},
     "env": {"PI_DIMENSIONAL_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "a.sol", "source_code": _MIXED, "unit_registry": _MIXED_REG},
     "env": {"PI_DIMENSIONAL_STRICT_MODE": "true"}},
]
