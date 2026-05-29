"""Parity spec for PiSolidityArrayLengthMutationSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityArrayLengthMutationSentry"

_mod = load_py_agent("pi_solidity_array_length_mutation_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityArrayLengthMutationSentry()
    out = agent.audit_array_length_mutation(_mod.ArrayLengthMutationInput(**data))
    return out.model_dump()


# Clean contract: no array-length mutation anywhere.
_SECURE = "\n".join(
    [
        "contract Safe {",
        "    function add(uint a, uint b) public pure returns (uint) {",
        "        return a + b;",
        "    }",
        "}",
    ]
)

# Direct assignment: arr.length = N
_DIRECT_ASSIGN = "\n".join(
    [
        "contract Vuln {",
        "    function shrink() public {",
        "        state.items.length = 0;",
        "    }",
        "}",
    ]
)

# Direct decrement: arr.length--  (matches [-+=/]?= ... actually '--' alone won't,
# but '-=' will). Use a compound-assign form the regex catches.
_DIRECT_COMPOUND = "\n".join(
    [
        "contract Vuln2 {",
        "    function bump() public {",
        "        self.buf.length += 5;",
        "    }",
        "}",
    ]
)

# Assembly mutation: assembly + sstore + length.
_ASSEMBLY = "\n".join(
    [
        "contract VulnAsm {",
        "    function grow() public {",
        "        assembly {",
        "            sstore(arr.slot, length)",
        "        }",
        "    }",
        "}",
    ]
)

# Multiple functions, mix of safe + vulnerable.
_MULTI = "\n".join(
    [
        "contract Mixed {",
        "    function ok(uint x) public pure returns (uint) { return x; }",
        "    function bad() public { data.arr.length = 3; }",
        "    function alsoBad() public {",
        "        assembly { sstore(s.slot, len) }",
        "    }",
        "}",
    ]
)

# Assembly present but no sstore -> NOT flagged (negative path).
_ASM_NO_SSTORE = "\n".join(
    [
        "contract NotVuln {",
        "    function read() public view {",
        "        assembly { let x := mload(0x40) }",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _DIRECT_ASSIGN}},
    {"input": {"file_path": "Vuln2.sol", "solidity_code": _DIRECT_COMPOUND}},
    {"input": {"file_path": "VulnAsm.sol", "solidity_code": _ASSEMBLY}},
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "NotVuln.sol", "solidity_code": _ASM_NO_SSTORE}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _DIRECT_ASSIGN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vuln.sol", "solidity_code": _DIRECT_ASSIGN},
     "env": {"PI_ARRAY_LENGTH_MUTATION_STRICT_MODE": "false"}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _DIRECT_ASSIGN},
     "env": {"PI_ARRAY_LENGTH_MUTATION_STRICT_MODE": "true"}},
]
