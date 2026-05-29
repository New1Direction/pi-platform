"""Parity spec for PiSolidityTxOriginCallCheckSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityTxOriginCallCheckSentry"

_mod = load_py_agent("pi_solidity_tx_origin_call_check_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityTxOriginCallCheckSentry()
    out = agent.audit_tx_origin_call(_mod.TxOriginCallCheckInput(**data))
    return out.model_dump()


# Clean contract: tx.origin never used in an authorization-bearing body.
_SECURE = "\n".join(
    [
        "contract Wallet {",
        "    address owner;",
        "    function deposit() public payable {",
        "        balances[msg.sender] += msg.value;",
        "    }",
        "}",
    ]
)

# Classic vulnerable require(tx.origin ...) in a named function.
_REQUIRE_TX_ORIGIN = "\n".join(
    [
        "contract Wallet {",
        "    function withdraw(uint amount) public {",
        "        require(tx.origin == owner, 'not owner');",
        "        owner.transfer(amount);",
        "    }",
        "}",
    ]
)

# tx.origin guarded by assert.
_ASSERT_TX_ORIGIN = "\n".join(
    [
        "contract Vault {",
        "    function drain() external {",
        "        assert(tx.origin == admin);",
        "        selfdestruct(payable(admin));",
        "    }",
        "}",
    ]
)

# tx.origin inside a fallback handler with an if check.
_FALLBACK_TX_ORIGIN = "\n".join(
    [
        "contract Proxy {",
        "    fallback() external payable {",
        "        if (tx.origin == controller) { execute(); }",
        "    }",
        "}",
    ]
)

# tx.origin inside a receive handler with an if check.
_RECEIVE_TX_ORIGIN = "\n".join(
    [
        "contract Sink {",
        "    receive() external payable {",
        "        if (tx.origin == owner) { revert(); }",
        "    }",
        "}",
    ]
)

# tx.origin present but NOT used in a guard (no require/assert/if) -> secure.
_TX_ORIGIN_NO_GUARD = "\n".join(
    [
        "contract Logger {",
        "    function log() public {",
        "        emit Caller(tx.origin);",
        "    }",
        "}",
    ]
)

# Multiple handlers: one safe, two vulnerable (named + receive).
_MULTI = "\n".join(
    [
        "contract Multi {",
        "    function safeOne() public { x = 1; }",
        "    function adminOnly() public { require(tx.origin == admin); }",
        "    receive() external payable { if (tx.origin == owner) { revert(); } }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Wallet.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Wallet.sol", "solidity_code": _REQUIRE_TX_ORIGIN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _ASSERT_TX_ORIGIN}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _FALLBACK_TX_ORIGIN}},
    {"input": {"file_path": "Sink.sol", "solidity_code": _RECEIVE_TX_ORIGIN}},
    {"input": {"file_path": "Logger.sol", "solidity_code": _TX_ORIGIN_NO_GUARD}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI, "check_level": "MEDIUM"}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Wallet.sol", "solidity_code": _REQUIRE_TX_ORIGIN},
     "env": {"PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE": "false"}},
    # strict env explicitly true -> REJECTED path
    {"input": {"file_path": "Wallet.sol", "solidity_code": _REQUIRE_TX_ORIGIN},
     "env": {"PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE": "true"}},
]
