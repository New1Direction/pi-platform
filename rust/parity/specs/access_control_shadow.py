"""Parity spec for PiAccessControlShadow.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiAccessControlShadow"

_mod = load_py_agent("pi_access_control_shadow.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAccessControlShadow()
    out = agent.audit_access_control(_mod.ACShadowInput(**data))
    return out.model_dump()


# Clean: admin function but it has an onlyOwner modifier -> secure.
_SECURE = "function withdraw() public onlyOwner { balance = 0; }"

# Vulnerable: admin function (emergency) missing any modifier.
_VULN_EMERGENCY = "function emergencyStop() public { paused = true; }"

# Vulnerable: admin function (mint) missing any modifier.
_VULN_MINT = "function mintTokens(address to) external { supply += 1; }"

# Non-admin function -> not flagged (transfer is not an admin keyword).
_NON_ADMIN = "function transfer(address to, uint amt) public { x = to; }"

# Modifier present elsewhere in the source (not in the body): the global
# `re.search(r'\bonlyRole\b', code)` branch should make this SECURE.
_MODIFIER_ELSEWHERE = "\n".join(
    [
        "modifier onlyRole(bytes32 r) { _; }",
        "function setOwnerAddress(address a) public { owner = a; }",
    ]
)

# Multiple functions: one secure admin (restricted), one vulnerable admin
# (withdraw), one non-admin.
_MULTI = "\n".join(
    [
        "function pauseContract() public restricted { paused = true; }",
        "function withdrawAll() public { msg.sender.transfer(address(this).balance); }",
        "function deposit() public payable { total += msg.value; }",
    ]
)

# Body spanning multiple lines (exercises the [\s\S]*? body group).
_MULTILINE_BODY = "\n".join(
    [
        "function adminReset()",
        "    public",
        "{",
        "    counter = 0;",
        "    flag = false;",
        "}",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # vulnerable emergency function, strict -> REJECTED
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_EMERGENCY},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # vulnerable mint function, strict -> REJECTED
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_MINT},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # non-admin function ignored -> PASSED
    {"input": {"file_path": "C.sol", "solidity_code": _NON_ADMIN},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # modifier defined elsewhere in source -> SECURE via global \b search
    {"input": {"file_path": "C.sol", "solidity_code": _MODIFIER_ELSEWHERE},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # multiple functions, mixed
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # multi-line body
    {"input": {"file_path": "C.sol", "solidity_code": _MULTILINE_BODY},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # empty / edge input
    {"input": {"file_path": "C.sol", "solidity_code": ""},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # check_level default omitted (uses STRICT default), vulnerable
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_EMERGENCY,
               "check_level": "MEDIUM"},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_EMERGENCY},
     "env": {"PI_AC_SHADOW_STRICT_MODE": "false"}},
]
