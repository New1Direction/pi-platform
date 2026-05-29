"""Parity spec for PiEIP712SignatureLinter.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiEIP712SignatureLinter"

_mod = load_py_agent("pi_eip712_signature_linter.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiEIP712SignatureLinter()
    out = agent.audit_signature_linter(_mod.EIP712LinterInput(**data))
    return out.model_dump()


# Secure: ecrecover present AND body uses block.chainid -> not vulnerable.
_SECURE_CHAINID = (
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    bytes32 ds = keccak256(abi.encode(block.chainid, address(this)));\n"
    "    address signer = ecrecover(h, v, r, s);\n"
    "    require(signer == owner);\n"
    "}"
)

# Secure: ecrecover present AND body references DOMAIN_SEPARATOR.
_SECURE_DOMAIN_SEP = (
    "function permit(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {\n"
    "    bytes32 digest = keccak256(abi.encodePacked(DOMAIN_SEPARATOR, h));\n"
    "    address recovered = ecrecover(digest, v, r, s);\n"
    "}"
)

# Vulnerable: ecrecover with no chainid / DOMAIN_SEPARATOR anywhere -> flagged.
_VULN_ECRECOVER = (
    "function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address signer = ecrecover(h, v, r, s);\n"
    "    require(signer == admin);\n"
    "}"
)

# Vulnerable via bare "recover" substring (e.g. ECDSA.recover), no chainid.
_VULN_RECOVER = (
    "function claim(bytes32 hash, bytes memory sig) public {\n"
    "    address a = ECDSA.recover(hash, sig);\n"
    "    balances[a] += 1;\n"
    "}"
)

# chainid lives in a DIFFERENT function body, but `"chainid" in code` suppresses
# the flag for the otherwise-vulnerable function -> whole contract is secure.
_CHAINID_ELSEWHERE = (
    "function a(bytes32 h, uint8 v) public {\n"
    "    address x = ecrecover(h, v, h, h);\n"
    "}\n"
    "function b() public view returns (uint256) {\n"
    "    return block.chainid;\n"
    "}"
)

# Multiple functions: one safe (DOMAIN_SEPARATOR), one without signature logic,
# one vulnerable. No chainid anywhere -> only the vulnerable one is flagged.
_MULTI = (
    "function add(uint256 a, uint256 b) public pure returns (uint256) {\n"
    "    return a + b;\n"
    "}\n"
    "function safe(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "    bytes32 ds = DOMAIN_SEPARATOR;\n"
    "}\n"
    "function bad(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
    "    address b = ecrecover(h, v, r, s);\n"
    "}"
)

# No functions / no signature verification -> trivially secure.
_NO_SIG = "function transfer(address to, uint256 amt) public { balances[to] += amt; }"

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_CHAINID}},
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_DOMAIN_SEP}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_ECRECOVER}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_RECOVER}},
    {"input": {"file_path": "C.sol", "solidity_code": _CHAINID_ELSEWHERE}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_SIG}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_ECRECOVER, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_ECRECOVER},
     "env": {"PI_EIP712_LINTER_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_ECRECOVER},
     "env": {"PI_EIP712_LINTER_STRICT_MODE": "true"}},
]
