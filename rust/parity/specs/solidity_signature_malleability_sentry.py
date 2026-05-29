"""Parity spec for PiSoliditySignatureMalleabilitySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSoliditySignatureMalleabilitySentry"

_mod = load_py_agent("pi_solidity_signature_malleability_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSoliditySignatureMalleabilitySentry()
    out = agent.audit_signature_malleability(
        _mod.SignatureMalleabilityInput(**data)
    )
    return out.model_dump()


# Clean / passing: ecrecover present but explicitly checks the s-value range.
_SAFE_S_CHECK = (
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "    require(a == owner);\n"
    "}"
)

# Lowercase variant of the s-value bound also suppresses the flag.
_SAFE_S_CHECK_LOWER = (
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0);\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}"
)

# Safe library: ECDSA.recover used inside the body (body also contains
# the "ecrecover" substring, so the ecrecover branch is entered, then the
# uses_safe_library check exonerates it).
_SAFE_LIBRARY = (
    "function claim(bytes32 h, bytes memory sig) public {\n"
    "    // fallback: ecrecover note\n"
    "    address a = ECDSA.recover(h, sig);\n"
    "}"
)

# Safe via contract-level "using ECDSA for" directive (matched on whole code,
# not just the function body).
_SAFE_USING = (
    "using ECDSA for bytes32;\n"
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}"
)

# Vulnerable: raw ecrecover, no library, no s-value check.
_VULN_RAW = (
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "    require(a == owner);\n"
    "}"
)

# Multiple functions: one safe (s-check), one vulnerable (raw).
_MULTI = (
    "function safeOne(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}\n"
    "function badOne(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address b = ecrecover(h, v, r, s);\n"
    "}\n"
    "function helper(uint x) public returns (uint) {\n"
    "    return x + 1;\n"
    "}"
)

# No signature logic at all.
_NO_SIG = "function add(uint a, uint b) public returns (uint) {\n    return a + b;\n}"

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _SAFE_S_CHECK}},
    {"input": {"file_path": "SafeLower.sol", "solidity_code": _SAFE_S_CHECK_LOWER}},
    {"input": {"file_path": "Lib.sol", "solidity_code": _SAFE_LIBRARY}},
    {"input": {"file_path": "Using.sol", "solidity_code": _SAFE_USING}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN_RAW}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Plain.sol", "solidity_code": _NO_SIG}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN_RAW, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN_RAW},
     "env": {"PI_SIGNATURE_MALLEABILITY_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path.
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN_RAW},
     "env": {"PI_SIGNATURE_MALLEABILITY_STRICT_MODE": "true"}},
]
