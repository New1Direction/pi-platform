"""Parity spec for PiTxOriginSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

NOTE: is_strict_mode() in the Python agent consults the env var
PI_TXORIGIN_STRICT_MODE first and falls back to an .antigravitycli/config.json
file (defaulting to strict=True). The Rust port only reads the env var. To keep
both sides deterministic and comparable, every sample pins PI_TXORIGIN_STRICT_MODE
explicitly via "env".
"""
from _util import load_py_agent

RUST_NAME = "PiTxOriginSentry"

_mod = load_py_agent("pi_tx_origin_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTxOriginSentry()
    out = agent.audit_tx_origin(_mod.TxOriginInput(**data))
    return out.model_dump()


_SECURE = "contract C {\n    function f() public {\n        require(msg.sender == owner);\n    }\n}"

_TXORIGIN = (
    "contract Wallet {\n"
    "    address owner;\n"
    "    function withdraw() public {\n"
    "        require(tx.origin == owner, \"not owner\");\n"
    "        payable(owner).transfer(address(this).balance);\n"
    "    }\n"
    "}"
)

# tx.origin appears only inside comments -> must NOT be flagged
_TXORIGIN_IN_COMMENT = (
    "contract C {\n"
    "    function f() public {\n"
    "        // legacy used tx.origin here\n"
    "        /* block comment with tx.origin too */\n"
    "        require(msg.sender == owner);\n"
    "    }\n"
    "}"
)

# ERC-2771 context: msg.sender directly -> compliance warning (but secure)
_EIP2771 = (
    "import \"@openzeppelin/contracts/metatx/ERC2771Context.sol\";\n"
    "contract Forwarded is ERC2771Context {\n"
    "    function action() public {\n"
    "        address sender = msg.sender;\n"
    "        doThing(sender);\n"
    "    }\n"
    "}"
)

# ERC-2771 context but already uses _msgSender() -> no compliance warning
_EIP2771_OK = (
    "contract Forwarded {\n"
    "    bool trusted = isTrustedForwarder(addr);\n"
    "    function action() public {\n"
    "        address sender = _msgSender();\n"
    "        require(msg.sender != address(0));\n"
    "    }\n"
    "}"
)

# Multiple functions: one vulnerable (tx.origin), one clean, plus a fallback.
_MULTI = (
    "contract Multi {\n"
    "    constructor() { owner = msg.sender; }\n"
    "    function safe() public view returns (address) { return owner; }\n"
    "    function risky() public { require(tx.origin == owner); }\n"
    "    fallback() external payable { revert(); }\n"
    "}"
)

# Function declaration with a body that never closes its brace -> skipped.
_UNCLOSED = "contract C {\n    function broken() public { require(tx.origin == x);\n"

# Interface-style declaration ending in ';' before '{' -> skipped (no body).
_INTERFACE = "interface I {\n    function ping() external returns (bool);\n}"

SAMPLES = [
    # clean / passing contract
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # tx.origin vulnerability, strict -> REJECTED
    {"input": {"file_path": "Wallet.sol", "solidity_code": _TXORIGIN},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # same vulnerability, non-strict -> WARN, is_secure coerced True
    {"input": {"file_path": "Wallet.sol", "solidity_code": _TXORIGIN},
     "env": {"PI_TXORIGIN_STRICT_MODE": "false"}},
    # tx.origin only in comments -> not flagged (comment stripping)
    {"input": {"file_path": "C.sol", "solidity_code": _TXORIGIN_IN_COMMENT},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # EIP-2771 context, direct msg.sender -> compliance warning, secure
    {"input": {"file_path": "Fwd.sol", "solidity_code": _EIP2771},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # EIP-2771 context using _msgSender() -> no compliance warning
    {"input": {"file_path": "Fwd.sol", "solidity_code": _EIP2771_OK},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # multiple functions, mixed findings, strict
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # unclosed brace -> function skipped, nothing flagged
    {"input": {"file_path": "C.sol", "solidity_code": _UNCLOSED},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # interface declaration (';' before '{') -> skipped
    {"input": {"file_path": "I.sol", "solidity_code": _INTERFACE},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # empty input -> no functions, passing
    {"input": {"file_path": "empty.sol", "solidity_code": ""},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
    # explicit non-default check_level, still vulnerable
    {"input": {"file_path": "Wallet.sol", "solidity_code": _TXORIGIN, "check_level": "MEDIUM"},
     "env": {"PI_TXORIGIN_STRICT_MODE": "true"}},
]
