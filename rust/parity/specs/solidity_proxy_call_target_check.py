"""Parity spec for PiSolidityProxyCallTargetCheck.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityProxyCallTargetCheck"

_mod = load_py_agent("pi_solidity_proxy_call_target_check.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityProxyCallTargetCheck()
    out = agent.audit_proxy_target(_mod.ProxyCallTargetInput(**data))
    return out.model_dump()


# Clean / passing: delegatecall target is a state var, not an arg.
_SAFE_STATEVAR = (
    "contract Proxy {\n"
    "    address public implementation;\n"
    "    function upgrade() public {\n"
    "        implementation.delegatecall(msg.data);\n"
    "    }\n"
    "}"
)

# Vulnerable: arg target via `target.delegatecall(...)`, no whitelist check.
_VULN_DOT = (
    "contract Proxy {\n"
    "    function execute(address target, bytes data) public {\n"
    "        target.delegatecall(data);\n"
    "    }\n"
    "}"
)

# Vulnerable: arg target via `delegatecall(..., target, ...)` form (assembly-ish).
_VULN_CALL = (
    "contract Proxy {\n"
    "    function execute(address impl, bytes payload) public {\n"
    "        bool ok = delegatecall(gas, impl, payload);\n"
    "    }\n"
    "}"
)

# Safe: arg target but guarded by a require whitelist check.
_SAFE_REQUIRE = (
    "contract Proxy {\n"
    "    mapping(address => bool) whitelist;\n"
    "    function execute(address target, bytes data) public {\n"
    "        require(whitelist[target], \"bad target\");\n"
    "        target.delegatecall(data);\n"
    "    }\n"
    "}"
)

# Safe: arg target guarded by isWhitelisted helper keyword.
_SAFE_ISWHITELISTED = (
    "contract Proxy {\n"
    "    function execute(address target, bytes data) public {\n"
    "        if (isWhitelisted(target)) {\n"
    "            target.delegatecall(data);\n"
    "        }\n"
    "    }\n"
    "}"
)

# delegatecall present but on a single-token (no-type) arg list -> arg_names empty,
# so is_arg_target stays False -> safe.
_DELEGATECALL_NO_TYPED_ARG = (
    "contract Proxy {\n"
    "    function execute(target) public {\n"
    "        target.delegatecall(data);\n"
    "    }\n"
    "}"
)

# Multiple functions: one vulnerable, one safe.
_MULTI = (
    "contract Proxy {\n"
    "    function bad(address t, bytes d) public {\n"
    "        t.delegatecall(d);\n"
    "    }\n"
    "    function good(address t2, bytes d2) public {\n"
    "        require(whitelist[t2]);\n"
    "        t2.delegatecall(d2);\n"
    "    }\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _SAFE_STATEVAR}},
    {"input": {"file_path": "VulnDot.sol", "solidity_code": _VULN_DOT}},
    {"input": {"file_path": "VulnCall.sol", "solidity_code": _VULN_CALL}},
    {"input": {"file_path": "SafeReq.sol", "solidity_code": _SAFE_REQUIRE}},
    {"input": {"file_path": "SafeWl.sol", "solidity_code": _SAFE_ISWHITELISTED}},
    {"input": {"file_path": "NoTyped.sol", "solidity_code": _DELEGATECALL_NO_TYPED_ARG}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "VulnDot.sol", "solidity_code": _VULN_DOT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "VulnDot.sol", "solidity_code": _VULN_DOT},
     "env": {"PI_PROXY_CALL_TARGET_STRICT_MODE": "false"}},
    {"input": {"file_path": "VulnDot.sol", "solidity_code": _VULN_DOT},
     "env": {"PI_PROXY_CALL_TARGET_STRICT_MODE": "true"}},
]
