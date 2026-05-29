"""Parity spec for PiAssemblyLethalWeapons.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

NOTE: the Python `is_strict_mode()` consults the PI_ASSEMBLY_STRICT_MODE env
var first and only falls back to a config file when it is unset. Every sample
sets that env var explicitly so behaviour is deterministic and matches the Rust
port (which mirrors only the env-var branch).
"""
from _util import load_py_agent

RUST_NAME = "PiAssemblyLethalWeapons"

_mod = load_py_agent("pi_assembly_lethal_weapons.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAssemblyLethalWeapons()
    out = agent.audit_assembly(_mod.AssemblySafetyInput(**data))
    return out.model_dump()


# --- Solidity fixtures --------------------------------------------------------

# Clean: a function with no assembly at all.
_CLEAN = "\n".join(
    [
        "contract C {",
        "    function add(uint a, uint b) public pure returns (uint) {",
        "        return a + b;",
        "    }",
        "}",
    ]
)

# Free-memory-pointer overwrite (0x40) -> vulnerable.
_FMP = "\n".join(
    [
        "contract C {",
        "    function corrupt() public {",
        "        assembly {",
        "            mstore(0x40, 0x80)",
        "        }",
        "    }",
        "}",
    ]
)

# Scratch-space write (0x20) -> vulnerable via the low-slot regex.
_SCRATCH = "\n".join(
    [
        "contract C {",
        "    function scratch() public {",
        "        assembly {",
        "            mstore(0x20, caller())",
        "        }",
        "    }",
        "}",
    ]
)

# Memory write but with 'allocate' in real code -> finding suppressed, secure.
_ALLOC_SUPPRESS = "\n".join(
    [
        "contract C {",
        "    function safe() public {",
        "        uint allocate = 1;",
        "        assembly {",
        "            mstore(0x40, 0x80)",
        "        }",
        "    }",
        "}",
    ]
)

# div/mul by power of two -> optimization findings only (still secure).
_OPT = "\n".join(
    [
        "contract C {",
        "    function opt(uint a) public {",
        "        assembly {",
        "            let r := div(a, 2)",
        "            let q := mul(a, 8)",
        "        }",
        "    }",
        "}",
    ]
)

# assembly block but no dangerous mstore / no opt -> secure, no findings.
_ASM_BENIGN = "\n".join(
    [
        "contract C {",
        "    function benign() public view returns (address a) {",
        "        assembly {",
        "            a := caller()",
        "        }",
        "    }",
        "}",
    ]
)

# Comments containing 'allocate' are stripped before the check, so this is
# still flagged as vulnerable (exercises the comment-stripping ordering).
_COMMENT_ALLOC = "\n".join(
    [
        "contract C {",
        "    function tricky() public {",
        "        assembly {",
        "            // allocate scratch space",
        "            mstore(0x0, 0x80)",
        "        }",
        "    }",
        "}",
    ]
)

# constructor + fallback + receive keyword name mapping, with a vulnerable body.
_SPECIAL_NAMES = "\n".join(
    [
        "contract C {",
        "    constructor() {",
        "        assembly {",
        "            mstore(64, 0x80)",
        "        }",
        "    }",
        "    fallback() external {",
        "        uint x = 0;",
        "    }",
        "}",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # free-memory-pointer overwrite -> REJECTED in strict
    {"input": {"file_path": "C.sol", "solidity_code": _FMP},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # scratch-space write -> vulnerable
    {"input": {"file_path": "C.sol", "solidity_code": _SCRATCH},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # 'allocate' present in real code -> suppressed, secure
    {"input": {"file_path": "C.sol", "solidity_code": _ALLOC_SUPPRESS},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # div/mul optimization findings, still secure
    {"input": {"file_path": "C.sol", "solidity_code": _OPT},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # benign assembly, no findings
    {"input": {"file_path": "C.sol", "solidity_code": _ASM_BENIGN},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # comment 'allocate' is stripped -> still vulnerable
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENT_ALLOC},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # constructor/fallback name mapping with vulnerable constructor
    {"input": {"file_path": "C.sol", "solidity_code": _SPECIAL_NAMES},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # empty input -> secure, no functions
    {"input": {"file_path": "C.sol", "solidity_code": ""},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "true"}},
    # non-strict env on a vulnerable input -> WARN path, is_secure coerced True
    {"input": {"file_path": "C.sol", "solidity_code": _FMP},
     "env": {"PI_ASSEMBLY_STRICT_MODE": "false"}},
]
