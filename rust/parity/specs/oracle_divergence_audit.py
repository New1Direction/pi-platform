"""Parity spec for PiOracleDivergenceAudit.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiOracleDivergenceAudit"

_mod = load_py_agent("pi_oracle_divergence_audit.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiOracleDivergenceAudit()
    out = agent.audit_divergence(_mod.OracleDivergenceInput(**data))
    return out.model_dump()


# Simple arithmetic-average Solidity that SHOULD be flagged (Mode 2).
_SIMPLE_AVG = (
    "function getPrice() public view returns (uint) {\n"
    "    uint sum = 0;\n"
    "    for (uint i = 0; i < prices.length; i++) { sum += prices[i]; }\n"
    "    return sum / prices.length; // naive arithmetic mean\n"
    "}"
)
# Geometric/sqrt-based aggregation that should NOT be flagged.
_GEOMETRIC = (
    "function getPrice() public view returns (uint) {\n"
    "    /* uses sqrt for geometric mean */\n"
    "    return sqrt(sum / prices.length);\n"
    "}"
)

SAMPLES = [
    # Clean feed within tolerance, no solidity code -> PASSED.
    {"input": {"file_path": "agg.sol", "prices": [3000.0, 3001.0],
               "benchmarks": [3000.0, 3000.5], "max_deviation_percent": 2.0,
               "solidity_code": ""}},
    # Divergent feed (one asset exceeds limit) -> REJECTED in strict default.
    {"input": {"file_path": "agg.sol", "prices": [3000.0, 4000.0],
               "benchmarks": [3000.0, 3000.0], "max_deviation_percent": 2.0,
               "solidity_code": ""}},
    # Multiple divergences + benchmark<=0 (skipped) + repr-tricky floats.
    {"input": {"file_path": "agg.sol",
               "prices": [100.0, 0.0, 1e20, 2950.123456789],
               "benchmarks": [50.0, 0.0, 1e18, 3000.0],
               "max_deviation_percent": 2.5, "solidity_code": ""}},
    # Simple arithmetic average solidity -> finding (but not vulnerable) PASSED.
    {"input": {"file_path": "agg.sol", "prices": [], "benchmarks": [],
               "max_deviation_percent": 2.0, "solidity_code": _SIMPLE_AVG}},
    # Geometric-mean solidity -> no finding.
    {"input": {"file_path": "agg.sol", "prices": [], "benchmarks": [],
               "max_deviation_percent": 2.0, "solidity_code": _GEOMETRIC}},
    # Both modes trip: divergent feed AND simple-average solidity.
    {"input": {"file_path": "agg.sol", "prices": [200.0], "benchmarks": [100.0],
               "max_deviation_percent": 2.0, "solidity_code": _SIMPLE_AVG}},
    # Empty/edge: empty arrays, defaults for max_deviation_percent & code.
    {"input": {"file_path": "agg.sol", "prices": [], "benchmarks": []}},
    # Mismatched lengths -> only min_len compared; benchmark extras ignored.
    {"input": {"file_path": "agg.sol", "prices": [3000.0, 9999.0, 1.0],
               "benchmarks": [3000.0], "max_deviation_percent": 2.0,
               "solidity_code": ""}},
    # Env: lenient mode -> divergent feed becomes WARN, is_secure coerced True.
    {"input": {"file_path": "agg.sol", "prices": [100.0], "benchmarks": [50.0],
               "max_deviation_percent": 2.0, "solidity_code": ""},
     "env": {"PI_ORACLE_DIV_STRICT_MODE": "false"}},
    # Env: explicit strict mode -> divergent feed REJECTED.
    {"input": {"file_path": "agg.sol", "prices": [100.0], "benchmarks": [50.0],
               "max_deviation_percent": 2.0, "solidity_code": ""},
     "env": {"PI_ORACLE_DIV_STRICT_MODE": "true"}},
]
