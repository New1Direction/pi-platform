"""Parity spec for PiGasGuzzlerDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGasGuzzlerDetector"

_mod = load_py_agent("pi_gas_guzzler_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGasGuzzlerDetector()
    out = agent.audit_gas(_mod.GasGuzzlerInput(**data))
    return out.model_dump()


# A loop that caches array length in a local variable -> NOT flagged.
_CLEAN = "\n".join(
    [
        "contract C {",
        "  function sum() public view returns (uint256) {",
        "    uint256 len = users.length;",
        "    uint256 total;",
        "    for (uint256 i = 0; i < len; i++) { total += users[i]; }",
        "    return total;",
        "  }",
        "}",
    ]
)

# Unbounded loop over a dynamic array's .length without caching -> vulnerable.
_UNBOUNDED = "\n".join(
    [
        "contract C {",
        "  function payAll() public {",
        "    for (uint256 i = 0; i < recipients.length; i++) {",
        "      recipients[i].transfer(1 ether);",
        "    }",
        "  }",
        "}",
    ]
)

# Loop with direct storage variable access, no memory/calldata -> gas opt finding
# (but not vulnerable -> still secure). Uses 's.' marker, caches length too.
_STORAGE_LOOP = "\n".join(
    [
        "contract C {",
        "  function tick() public {",
        "    uint256 len = items;",
        "    for (uint256 i = 0; i < len; i++) {",
        "      s.counter += 1;",
        "    }",
        "  }",
        "}",
    ]
)

# 'memory' array parameter -> calldata gas opt finding (not vulnerable).
_MEMORY_PARAM = "\n".join(
    [
        "contract C {",
        "  function process(uint256[] memory data) public {",
        "    uint256 x = data[0];",
        "  }",
        "}",
    ]
)

# Unbounded .length loop but inside a // comment that is stripped -> NOT flagged.
_COMMENTED = "\n".join(
    [
        "contract C {",
        "  function noop() public {",
        "    // for (uint256 i = 0; i < users.length; i++) { skip(); }",
        "    uint256 z = 1;",
        "    while (z < 10) { z++; }",
        "  }",
        "}",
    ]
)

# Block comment (/* */) containing a .length loop -> stripped -> NOT flagged.
_BLOCK_COMMENTED = "\n".join(
    [
        "contract C {",
        "  function noop2() public {",
        "    /* for (uint256 i = 0; i < arr.length; i++) {} */",
        "    for (uint256 j = 0; j < 3; j++) {}",
        "  }",
        "}",
    ]
)

# Multiple functions: a clean one and an unbounded one in the same contract.
_MULTI = "\n".join(
    [
        "contract C {",
        "  constructor() {",
        "    owner = msg.sender;",
        "  }",
        "  function safe() public {",
        "    uint256 len = a.length;",
        "    for (uint256 i = 0; i < len; i++) {}",
        "  }",
        "  function unsafe() public {",
        "    for (uint256 i = 0; i < holders.length; i++) {}",
        "  }",
        "  function takeMem(bytes[] memory b) public {}",
        "}",
    ]
)

SAMPLES = [
    # Clean, passing contract.
    {"input": {"file_path": "Clean.sol", "solidity_code": _CLEAN}},
    # Unbounded loop -> strict default -> REJECTED.
    {"input": {"file_path": "Unbounded.sol", "solidity_code": _UNBOUNDED}},
    # Direct storage access in loop -> gas opt finding, still secure.
    {"input": {"file_path": "Storage.sol", "solidity_code": _STORAGE_LOOP}},
    # memory array param -> calldata gas opt finding, still secure.
    {"input": {"file_path": "Mem.sol", "solidity_code": _MEMORY_PARAM}},
    # Loop in a line comment is stripped before analysis.
    {"input": {"file_path": "Commented.sol", "solidity_code": _COMMENTED}},
    # Loop in a block comment is stripped before analysis.
    {"input": {"file_path": "Block.sol", "solidity_code": _BLOCK_COMMENTED}},
    # Multiple functions with mixed verdicts.
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    # Empty / edge input: no functions at all.
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # Vulnerable input with non-strict env -> WARN path, is_secure coerced True.
    {"input": {"file_path": "Unbounded.sol", "solidity_code": _UNBOUNDED},
     "env": {"PI_GAS_STRICT_MODE": "false"}},
    # Vulnerable input with strict env -> REJECTED path.
    {"input": {"file_path": "Unbounded.sol", "solidity_code": _UNBOUNDED},
     "env": {"PI_GAS_STRICT_MODE": "true"}},
]
