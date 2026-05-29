"""Parity spec for PiSolidityUnboundedLoopsInStateMutation.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityUnboundedLoopsInStateMutation"

_mod = load_py_agent("pi_solidity_unbounded_loops_in_state_mutation.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityUnboundedLoopsInStateMutation()
    out = agent.audit_unbounded_loops(_mod.UnboundedLoopsStateInput(**data))
    return out.model_dump()


# --- Solidity fixtures ---------------------------------------------------

# Clean: a loop that only reads state, no mutation -> secure / PASSED.
_CLEAN = (
    "contract C {\n"
    "    function sumView() public view returns (uint) {\n"
    "        uint s = 0;\n"
    "        for (uint i = 0; i < arr.length; i++) {\n"
    "            uint x = arr[i];\n"
    "        }\n"
    "        return s;\n"
    "    }\n"
    "}"
)

# Vulnerable path A: `.length`-driven unbounded for-loop with an array index
# write -> assignment detected -> flagged.
_LENGTH_WRITE = (
    "function withdrawAll(address[] memory users) public {\n"
    "    for (uint i = 0; i < users.length; i++) {\n"
    "        balances[users[i]] = 0;\n"
    "    }\n"
    "}"
)

# Vulnerable path B: while-loop with NO condition group (group(2) == '') ->
# is_unbounded immediately, with a `.push` mutation.
_WHILE_PUSH = (
    "function drain() public {\n"
    "    while (queue.length > 0) {\n"
    "        history.push(queue[0]);\n"
    "    }\n"
    "}"
)

# Vulnerable path C: parameter-driven loop var that is NOT validated anywhere
# in the body (no require/assert/if referencing it) -> unbounded; mutation via
# compound assignment `+=`.
_UNVALIDATED_PARAM = (
    "function tally(uint cap) public {\n"
    "    for (uint i = 0; i < cap; i++) {\n"
    "        total += i;\n"
    "    }\n"
    "}"
)

# Vulnerable path D: state mutation via inline assembly `sstore` (no `=`).
_SSTORE = (
    "function poke(uint n) public {\n"
    "    for (uint i = 0; i < n; i++) {\n"
    "        assembly { sstore(i, 1) }\n"
    "    }\n"
    "}"
)

# Bounded/validated: loop var `cap` IS referenced by a require() in the body, so
# the validation_pattern matches -> NOT unbounded -> secure.
_VALIDATED = (
    "function bounded(uint cap) public {\n"
    "    require(cap < 100);\n"
    "    for (uint i = 0; i < cap; i++) {\n"
    "        total += i;\n"
    "    }\n"
    "}"
)

# Multiple functions: only one is vulnerable; exercises the per-function loop
# plus the inner break (first vulnerable loop ends the function scan).
_MULTI = (
    "function a() public { for (uint i = 0; i < x.length; i++) { y = 1; } }\n"
    "function b() public view { for (uint j = 0; j < x.length; j++) { uint z = x[j]; } }"
)

# Nested unbounded loops both mutating; brace-matching must capture the full
# outer body so the loop-body regex still finds the assignment.
_NESTED = (
    "function grid() public {\n"
    "    for (uint i = 0; i < rows.length; i++) {\n"
    "        for (uint j = 0; j < cols.length; j++) {\n"
    "            grid[i][j] = 0;\n"
    "        }\n"
    "    }\n"
    "}"
)


SAMPLES = [
    # clean read-only loop
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    # distinct vulnerable paths
    {"input": {"file_path": "C.sol", "solidity_code": _LENGTH_WRITE}},
    {"input": {"file_path": "C.sol", "solidity_code": _WHILE_PUSH}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_PARAM}},
    {"input": {"file_path": "C.sol", "solidity_code": _SSTORE}},
    # validated -> not flagged
    {"input": {"file_path": "C.sol", "solidity_code": _VALIDATED}},
    # multiple functions, mixed
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    # nested loops
    {"input": {"file_path": "C.sol", "solidity_code": _NESTED}},
    # empty edge input
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # explicit check_level field (default-able) carried through
    {"input": {"file_path": "C.sol", "solidity_code": _LENGTH_WRITE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _LENGTH_WRITE},
     "env": {"PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED
    {"input": {"file_path": "C.sol", "solidity_code": _LENGTH_WRITE},
     "env": {"PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE": "true"}},
]
