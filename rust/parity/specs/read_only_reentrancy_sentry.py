"""Parity spec for PiReadOnlyReentrancySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiReadOnlyReentrancySentry"

_mod = load_py_agent("pi_read_only_reentrancy_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiReadOnlyReentrancySentry()
    out = agent.audit_readonly_reentrancy(_mod.ReadOnlyReentrancyInput(**data))
    return out.model_dump()


# Clean, properly guarded view function -> PASSED.
_SECURE = "\n".join(
    [
        "contract Safe {",
        "    function getPrice() public view returns (uint) {",
        "        require(!locked);",
        "        return pool.get_virtual_price();",
        "    }",
        "}",
    ]
)

# Read-only reentrancy: queries get_virtual_price with no guard -> vulnerable.
_VIRTUAL_PRICE = "\n".join(
    [
        "contract Vuln {",
        "    function getPrice() public view returns (uint) {",
        "        return pool.get_virtual_price();",
        "    }",
        "}",
    ]
)

# balanceOf query, no guard -> vulnerable.
_BALANCEOF = "\n".join(
    [
        "contract Vuln {",
        "    function getBal() external view returns (uint) {",
        "        return token.balanceOf(address(this));",
        "    }",
        "}",
    ]
)

# get_dy query, no guard -> vulnerable.
_GET_DY = "\n".join(
    [
        "contract Vuln {",
        "    function quote() public view returns (uint) {",
        "        return curve.get_dy(0, 1, amount);",
        "    }",
        "}",
    ]
)

# View function depending on block.timestamp without require -> WARN finding
# (but NOT a vulnerable_function, so is_secure stays true).
_TIMESTAMP = "\n".join(
    [
        "contract T {",
        "    function age() public view returns (uint) {",
        "        return block.timestamp - start;",
        "    }",
        "}",
    ]
)

# Comments that contain the trigger keywords should be stripped before scanning,
# so this stays secure (keyword only appears inside comments).
_COMMENTED = "\n".join(
    [
        "contract C {",
        "    function safe() public view returns (uint) {",
        "        // get_virtual_price balanceOf get_dy are mentioned here only",
        "        /* balanceOf block.timestamp in a block comment */",
        "        return 1;",
        "    }",
        "}",
    ]
)

# Multiple functions: one vulnerable (balanceOf, no guard) + one timestamp warn.
_MULTI = "\n".join(
    [
        "contract Multi {",
        "    function a() public view returns (uint) {",
        "        return token.balanceOf(msg.sender);",
        "    }",
        "    function b() public view returns (uint) {",
        "        return block.timestamp;",
        "    }",
        "    constructor() {",
        "        owner = msg.sender;",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VIRTUAL_PRICE}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _BALANCEOF}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _GET_DY}},
    {"input": {"file_path": "T.sol", "solidity_code": _TIMESTAMP}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENTED}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _BALANCEOF, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VIRTUAL_PRICE},
     "env": {"PI_READONLY_REENTRANCY_STRICT_MODE": "false"}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VIRTUAL_PRICE},
     "env": {"PI_READONLY_REENTRANCY_STRICT_MODE": "true"}},
]
