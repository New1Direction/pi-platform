"""Parity spec for PiSolidityFlashLoanAttack.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityFlashLoanAttack"

_mod = load_py_agent("pi_solidity_flash_loan_attack.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityFlashLoanAttack()
    out = agent.audit_flash_loan(_mod.SolidityFlashLoanInput(**data))
    return out.model_dump()


# Clean: callback verifies msg.sender == pool.
_CLEAN = "\n".join(
    [
        "contract Vault {",
        "    function executeOperation(address asset, uint amount) external returns (bool) {",
        "        require(msg.sender == pool);",
        "        repay(amount);",
        "    }",
        "}",
    ]
)

# Vulnerable: executeOperation callback with no sender verification.
_VULN_EXEC = "\n".join(
    [
        "contract Vault {",
        "    function executeOperation(address asset, uint amount) external returns (bool) {",
        "        drainReserves();",
        "    }",
        "}",
    ]
)

# Vulnerable: flashLoan callback, also unverified.
_VULN_FLASHLOAN = "\n".join(
    [
        "function flashLoan(uint256 amount) public {",
        "    pool.lend(amount);",
        "    swap();",
        "}",
    ]
)

# Parity gotcha: `onlyPool` sits in the Solidity modifier position (after the
# parens), so it is NOT captured by the args group `(.*?)` and the callback is
# still flagged. Kept as a diverse sample that exercises this exact edge.
_MODIFIER_AFTER_PARENS = "\n".join(
    [
        "function receiveFlashLoan(uint256 amount) onlyPool external {",
        "    settle(amount);",
        "}",
    ]
)

# Safe via the literal string `onlyPool` appearing inside the parens, i.e.
# captured by the args group. (Not idiomatic Solidity, but it is the only way
# the `"onlyPool" in args` branch fires — covers that path.)
_SAFE_ARGS_MODIFIER = "\n".join(
    [
        "function executeOperation(address asset /* onlyPool */) external {",
        "    settle();",
        "}",
    ]
)

# Safe via modifier name appearing in the body (onlyLendingPool).
_SAFE_BODY_MODIFIER = "\n".join(
    [
        "function receiveFlashLoan(uint256 amount) external {",
        "    onlyLendingPool();",
        "    settle(amount);",
        "}",
    ]
)

# Multiple functions: one safe, one vulnerable, one non-callback (ignored).
_MULTI = "\n".join(
    [
        "contract Multi {",
        "    function transfer(address to, uint amt) public {",
        "        balances[to] += amt;",
        "    }",
        "    function executeOperation(address a, uint amt) external returns (bool) {",
        "        require(msg.sender == lendingPool);",
        "    }",
        "    function receiveFlashLoan(uint256 amt) external {",
        "        manipulateStorage();",
        "    }",
        "}",
    ]
)

# Non-callback only: no flash-loan-related names -> always secure.
_NON_CALLBACK = "\n".join(
    [
        "function deposit(uint256 amount) public {",
        "    balances[msg.sender] += amount;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_EXEC}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_FLASHLOAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MODIFIER_AFTER_PARENS}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _SAFE_ARGS_MODIFIER}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _SAFE_BODY_MODIFIER}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Plain.sol", "solidity_code": _NON_CALLBACK}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_EXEC, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_EXEC},
     "env": {"PI_SOLIDITY_FLASH_LOAN_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_EXEC},
     "env": {"PI_SOLIDITY_FLASH_LOAN_STRICT_MODE": "true"}},
]
