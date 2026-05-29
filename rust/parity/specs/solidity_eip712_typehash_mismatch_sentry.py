"""Parity spec for PiSolidityEIP712TypehashMismatchSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityEIP712TypehashMismatchSentry"

_mod = load_py_agent("pi_solidity_eip712_typehash_mismatch_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityEIP712TypehashMismatchSentry()
    out = agent.audit_typehash_alignment(_mod.EIP712TypehashMismatchInput(**data))
    return out.model_dump()


# A clean, perfectly aligned struct/typehash pair.
_CLEAN = "\n".join(
    [
        "struct Mail {",
        "    address from;",
        "    address to;",
        "    string contents;",
        "}",
        'bytes32 constant MAIL_TYPEHASH = keccak256("Mail(address from,address to,string contents)");',
    ]
)

# Mismatched parameter COUNT (typehash drops a field).
_COUNT_MISMATCH = "\n".join(
    [
        "struct Mail {",
        "    address from;",
        "    address to;",
        "    string contents;",
        "}",
        'bytes32 constant MAIL_TYPEHASH = keccak256("Mail(address from,address to)");',
    ]
)

# Mismatched parameter NAME (qty vs amount).
_NAME_MISMATCH = "\n".join(
    [
        "struct Order {",
        "    uint256 amount;",
        "    address buyer;",
        "}",
        'bytes32 constant ORDER_TYPEHASH = keccak256("Order(uint256 qty,address buyer)");',
    ]
)

# Two structs, one good typehash, one bad typehash.
_MULTI = "\n".join(
    [
        "struct A { uint256 x; address y; }",
        "struct B { bytes32 h; }",
        'bytes32 constant A_TYPEHASH = keccak256("A(uint256 x,address y)");',
        'bytes32 constant B_TYPEHASH = keccak256("B(bytes32 wrong)");',
    ]
)

# TYPEHASH whose struct is never declared -> skipped entirely (passes).
_NO_STRUCT = 'bytes32 constant FOO_TYPEHASH = keccak256("Ghost(address a)");'

# Array-typed member, perfectly aligned.
_ARRAY_OK = "\n".join(
    [
        "struct Batch {",
        "    uint256[] amounts;",
        "    address to;",
        "}",
        'bytes32 constant BATCH_TYPEHASH = keccak256("Batch(uint256[] amounts,address to)");',
    ]
)

# Extra internal whitespace in the signature should normalize to a match.
_SPACING_OK = "\n".join(
    [
        "struct D { uint256 v; }",
        'bytes32 D_TYPEHASH = keccak256("D(uint256    v)");',
    ]
)

SAMPLES = [
    {"input": {"file_path": "Clean.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Count.sol", "solidity_code": _COUNT_MISMATCH}},
    {"input": {"file_path": "Name.sol", "solidity_code": _NAME_MISMATCH}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "NoStruct.sol", "solidity_code": _NO_STRUCT}},
    {"input": {"file_path": "Array.sol", "solidity_code": _ARRAY_OK}},
    {"input": {"file_path": "Spacing.sol", "solidity_code": _SPACING_OK}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Lenient.sol", "solidity_code": _COUNT_MISMATCH, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Warn.sol", "solidity_code": _NAME_MISMATCH},
     "env": {"PI_EIP712_TYPEHASH_STRICT_MODE": "false"}},
    # strict env -> REJECTED path.
    {"input": {"file_path": "Strict.sol", "solidity_code": _NAME_MISMATCH},
     "env": {"PI_EIP712_TYPEHASH_STRICT_MODE": "true"}},
]
