"""Parity spec for PiReentrancyGuardSpec.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiReentrancyGuardSpec"

_mod = load_py_agent("pi_reentrancy_guard_spec.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiReentrancyGuardSpec()
    out = agent.audit_reentrancy_spec(_mod.ReentrancyGuardSpecInput(**data))
    return out.model_dump()


# .call(...) before a state write, no nonReentrant modifier -> vulnerable.
_VULN_CALL = "function withdraw() public { msg.sender.call(\"\"); balance = 0; }"
# .send(...) before a `total -= amount` write -> vulnerable (send path).
_VULN_SEND = "function payOut() public { recipient.send(amount); total -= amount; }"
# Has the nonReentrant modifier -> safe.
_SAFE_MODIFIER = "function withdraw() public nonReentrant { msg.sender.call(\"\"); balance = 0; }"
# No external call at all -> safe.
_SAFE_NOCALL = "function deposit() public { balance += msg.value; }"
# State write happens BEFORE the external call (CEI respected) -> safe.
_SAFE_ORDER = "function safe() public { balance = 0; msg.sender.transfer(balance); }"
# No function blocks at all.
_NO_FUNCS = "contract C { uint256 x; }"
# Two functions: first is vulnerable, second is clean.
_MULTI = "function a() public { other.call(\"\"); x = 1; } function b() public { y += 2; }"

SAMPLES = [
    # clean / passing inputs
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_NOCALL}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_MODIFIER}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_ORDER}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_FUNCS}},
    # vulnerable paths (pin strict mode so the result is deterministic and
    # independent of any on-disk ~/.antigravitycli/config.json fallback)
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CALL},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_SEND},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "true"}},
    # edge: empty source
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, but exercises the field)
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CALL, "check_level": "MEDIUM"},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "true"}},
    # env branches: strict -> REJECTED, non-strict -> WARN + is_secure coerced True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CALL},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CALL},
     "env": {"PI_REENTRANCY_SPEC_STRICT_MODE": "false"}},
]
