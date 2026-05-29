"""Parity spec for PiSolidityOwnerTimelockSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityOwnerTimelockSentry"

_mod = load_py_agent("pi_solidity_owner_timelock_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityOwnerTimelockSentry()
    out = agent.audit_owner_timelock(_mod.OwnerTimelockInput(**data))
    return out.model_dump()


# A vulnerable admin function: onlyOwner, no timelock, not a low-risk name.
_VULN = "function withdraw(uint256 amount) public onlyOwner { balance -= amount; }"

# Two vulnerable admin functions in one contract.
_VULN_MULTI = "\n".join(
    [
        "contract Vault {",
        "    function setFee(uint256 fee) external onlyOwner { feeBps = fee; }",
        "    function drain(address to) external onlyOwner { to.transfer(address(this).balance); }",
        "}",
    ]
)

# Has a timelock mechanism keyword ('delay') -> not vulnerable even with onlyOwner.
_TIMELOCK = "\n".join(
    [
        "contract Vault {",
        "    uint256 public minDelay;",
        "    function withdraw(uint256 amount) external onlyOwner { _enforceDelay(); }",
        "}",
    ]
)

# onlyOwner but low-risk name (getter) -> excluded.
_LOWRISK = "function getConfig() external onlyOwner { return config; }"

# A function with NO onlyOwner modifier -> not an admin action -> secure.
_NO_OWNER = "function deposit() external payable { balance += msg.value; }"

# Mix: a getter (excluded), a setter (flagged), and a renounce (excluded by 'renounce').
_MIXED = "\n".join(
    [
        "contract Admin {",
        "    function getOwner() external onlyOwner { return owner; }",
        "    function setOracle(address o) external onlyOwner { oracle = o; }",
        "    function renounceOwnership() external onlyOwner { owner = address(0); }",
        "}",
    ]
)

SAMPLES = [
    # 1. clean / passing (no admin functions)
    {"input": {"file_path": "C.sol", "solidity_code": _NO_OWNER}},
    # 2. single vulnerable admin function
    {"input": {"file_path": "C.sol", "solidity_code": _VULN}},
    # 3. multiple vulnerable admin functions
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_MULTI}},
    # 4. timelock mechanism present -> secure
    {"input": {"file_path": "C.sol", "solidity_code": _TIMELOCK}},
    # 5. low-risk getter name excluded
    {"input": {"file_path": "C.sol", "solidity_code": _LOWRISK}},
    # 6. mixed: getter+renounce excluded, setter flagged
    {"input": {"file_path": "C.sol", "solidity_code": _MIXED}},
    # 7. empty / edge input
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # 8. explicit check_level override (does not affect logic)
    {"input": {"file_path": "C.sol", "solidity_code": _VULN, "check_level": "MEDIUM"}},
    # 9. non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN},
     "env": {"PI_OWNER_TIMELOCK_STRICT_MODE": "false"}},
    # 10. explicit strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _VULN},
     "env": {"PI_OWNER_TIMELOCK_STRICT_MODE": "true"}},
]
