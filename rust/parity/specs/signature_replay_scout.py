"""Parity spec for PiSignatureReplayScout.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSignatureReplayScout"

_mod = load_py_agent("pi_signature_replay_scout.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSignatureReplayScout()
    out = agent.audit_signature(_mod.SignatureInput(**data))
    return out.model_dump()


# Clean / passing: ecrecover present but guarded by a nonce.
_SECURE_NONCE = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract Vault {",
        "    mapping(address => uint256) public nonces;",
        "    function claim(uint256 nonce, uint8 v, bytes32 r, bytes32 s) public {",
        "        require(nonce == nonces[msg.sender]);",
        "        address signer = ecrecover(keccak256(abi.encode(nonce)), v, r, s);",
        "    }",
        "}",
    ]
)

# Vulnerable: bare ecrecover, no DOMAIN_SEPARATOR, no nonce/chainId.
_VULN_ECRECOVER = "\n".join(
    [
        "contract Bad {",
        "    function execute(uint8 v, bytes32 r, bytes32 s) public {",
        "        address signer = ecrecover(hash, v, r, s);",
        "        balances[signer] += 1;",
        "    }",
        "}",
    ]
)

# Vulnerable via ECDSA.recover (alternate recovery API).
_VULN_ECDSA = "\n".join(
    [
        "contract Bad2 {",
        "    function withdraw(bytes memory sig) external {",
        "        address signer = ECDSA.recover(digest, sig);",
        "        _pay(signer);",
        "    }",
        "}",
    ]
)

# Safe via global DOMAIN_SEPARATOR even though function uses ecrecover.
_SAFE_DOMAIN = "\n".join(
    [
        "contract Eip712 {",
        "    bytes32 public DOMAIN_SEPARATOR = keccak256('x');",
        "    function permit(uint8 v, bytes32 r, bytes32 s) public {",
        "        address signer = ecrecover(digest, v, r, s);",
        "    }",
        "}",
    ]
)

# Safe via chainId tracking inside the body.
_SAFE_CHAINID = "\n".join(
    [
        "contract Eip712b {",
        "    function permit(uint8 v, bytes32 r, bytes32 s) public {",
        "        uint256 chainId = block.chainid;",
        "        address signer = ecrecover(digest, v, r, s);",
        "    }",
        "}",
    ]
)

# Constructor with ecrecover is skipped; trailing vulnerable function still caught.
_CONSTRUCTOR_SKIP = "\n".join(
    [
        "contract C {",
        "    constructor() {",
        "        address a = ecrecover(h, v, r, s);",
        "    }",
        "    function relay(uint8 v, bytes32 r, bytes32 s) public {",
        "        address b = ecrecover(h2, v, r, s);",
        "    }",
        "}",
    ]
)

# Comment-only ecrecover should be stripped and NOT flagged.
_COMMENTED_OUT = "\n".join(
    [
        "contract Commented {",
        "    function f() public {",
        "        // address signer = ecrecover(h, v, r, s);",
        "        /* ecrecover(a, b, c, d) is documented here */",
        "        uint256 x = 1;",
        "    }",
        "}",
    ]
)

# Abstract function declaration (semicolon before brace) -> not a concrete body.
_ABSTRACT_DECL = "\n".join(
    [
        "interface I {",
        "    function verify(bytes32 h) external returns (address);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE_NONCE}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _VULN_ECRECOVER}},
    {"input": {"file_path": "Bad2.sol", "solidity_code": _VULN_ECDSA}},
    {"input": {"file_path": "Eip712.sol", "solidity_code": _SAFE_DOMAIN}},
    {"input": {"file_path": "Eip712b.sol", "solidity_code": _SAFE_CHAINID}},
    {"input": {"file_path": "C.sol", "solidity_code": _CONSTRUCTOR_SKIP}},
    {"input": {"file_path": "Commented.sol", "solidity_code": _COMMENTED_OUT}},
    {"input": {"file_path": "I.sol", "solidity_code": _ABSTRACT_DECL}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bad.sol", "solidity_code": _VULN_ECRECOVER},
     "env": {"PI_SIGNATURE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Bad.sol", "solidity_code": _VULN_ECRECOVER},
     "env": {"PI_SIGNATURE_STRICT_MODE": "true"}},
]
