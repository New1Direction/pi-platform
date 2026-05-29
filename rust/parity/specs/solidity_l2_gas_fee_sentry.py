"""Parity spec for PiSolidityL2GasFeeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityL2GasFeeSentry"

_mod = load_py_agent("pi_solidity_l2_gas_fee_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityL2GasFeeSentry()
    out = agent.audit_l2_gas_fee(_mod.L2GasFeeInput(**data))
    return out.model_dump()


# --- Solidity fixtures -------------------------------------------------------

# Clean: only fixed-size value params, no dynamic [] or bytes -> PASSED.
_CLEAN = (
    "function transfer(address to, uint256 amount) external {\n"
    "    balances[to] += amount;\n"
    "}"
)

# Dynamic array param without a length boundary check -> flagged.
_UNBOUNDED_ARRAY = (
    "function batchSend(address[] recipients, uint256[] amounts) public {\n"
    "    for (uint i = 0; i < recipients.length; i++) {\n"
    "        recipients[i].transfer(amounts[i]);\n"
    "    }\n"
    "}"
)

# bytes param WITH a require(...length <= MAX) boundary -> secure.
_BOUNDED_BYTES = (
    "function safeBatch(bytes data) external {\n"
    "    require(data.length <= 100, \"too big\");\n"
    "    process(data);\n"
    "}"
)

# bytes param with NO length check at all -> flagged.
_UNBOUNDED_BYTES = (
    "function ingest(bytes payload) external {\n"
    "    store(payload);\n"
    "}"
)

# Mixed contract: one safe, one unbounded array, one bounded bytes, plus an
# internal (non-public/external) function that must be ignored entirely.
_MIXED = (
    "function ok(uint256 a) public {\n"
    "    total += a;\n"
    "}\n"
    "\n"
    "function unbounded(uint256[] vals) external {\n"
    "    for (uint i = 0; i < vals.length; i++) { sum += vals[i]; }\n"
    "}\n"
    "\n"
    "function bounded(bytes blob) public {\n"
    "    require(blob.length < 256);\n"
    "    emit Blob(blob);\n"
    "}\n"
    "\n"
    "function _internalHelper(bytes raw) internal {\n"
    "    raw;\n"
    "}"
)

# Empty body immediately followed by another function on the next line: the
# Python lookahead `\n\s*function` makes the first body empty. Exercises the
# manual-scanner edge case.
_EMPTY_BODY_THEN_FUNC = (
    "function first(bytes a) external {\n"
    "function second(uint256[] b) public {\n"
    "    require(b.length == 3);\n"
    "}"
)

# Visibility keyword appears as a SUBSTRING (publicfoo) and modifiers/returns
# sit between ) and the real visibility token.
_VIS_SUBSTRING = (
    "function quirky(bytes data) view publicfoo returns (uint) {\n"
    "    return data.length;\n"
    "}"
)

SAMPLES = [
    # clean passing input
    {"input": {"file_path": "Clean.sol", "solidity_code": _CLEAN}},
    # distinct flagged path: unbounded dynamic array
    {"input": {"file_path": "Batch.sol", "solidity_code": _UNBOUNDED_ARRAY}},
    # secure path: bytes with explicit length boundary
    {"input": {"file_path": "Safe.sol", "solidity_code": _BOUNDED_BYTES}},
    # distinct flagged path: bytes with no length check
    {"input": {"file_path": "Ingest.sol", "solidity_code": _UNBOUNDED_BYTES}},
    # multi-function mixed contract
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED}},
    # lookahead empty-body edge case
    {"input": {"file_path": "Edge.sol", "solidity_code": _EMPTY_BODY_THEN_FUNC}},
    # visibility-substring / modifiers edge case
    {"input": {"file_path": "Quirk.sol", "solidity_code": _VIS_SUBSTRING}},
    # empty/edge input
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, but exercises the field)
    {"input": {"file_path": "Batch.sol", "solidity_code": _UNBOUNDED_ARRAY,
               "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Batch.sol", "solidity_code": _UNBOUNDED_ARRAY},
     "env": {"PI_L2_GAS_FEE_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "Batch.sol", "solidity_code": _UNBOUNDED_ARRAY},
     "env": {"PI_L2_GAS_FEE_STRICT_MODE": "true"}},
]
