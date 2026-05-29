"""Parity spec for PiSoliditySignatureOmittedReplaySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSoliditySignatureOmittedReplaySentry"

_mod = load_py_agent("pi_solidity_signature_omitted_replay_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSoliditySignatureOmittedReplaySentry()
    out = agent.audit_signature_replay(_mod.SignatureOmittedReplayInput(**data))
    return out.model_dump()


# Secure: hashes with both nonce and block.chainid -> no vulnerability.
_SECURE = (
    "function hashOrder(uint256 amount) public view returns (bytes32) {\n"
    "    return keccak256(abi.encode(amount, nonces[msg.sender], block.chainid));\n"
    "}"
)

# Missing both chainid and nonce.
_MISSING_BOTH = (
    "function permitHash(address owner, uint256 value) internal pure returns (bytes32) {\n"
    "    return keccak256(abi.encode(owner, value));\n"
    "}"
)

# Missing only chainid (has nonce).
_MISSING_CHAINID = (
    "function verifyDigest(bytes32 data) public view returns (bytes32) {\n"
    "    return keccak256(abi.encodePacked(data, nonce));\n"
    "}"
)

# Missing only nonce (has chainid).
_MISSING_NONCE = (
    "function signatureHash(uint256 v) public view returns (bytes32) {\n"
    "    return keccak256(abi.encode(v, block.chainid));\n"
    "}"
)

# Function name does not match the signature keywords -> ignored even though it
# omits chainid/nonce.
_NAME_NOT_MATCHED = (
    "function transferTokens(uint256 v) public { \n"
    "    bytes32 h = keccak256(abi.encode(v)); \n"
    "}"
)

# Multiple functions in one file: one secure, one vulnerable.
_MULTI = (
    "contract Wallet {\n"
    "    function hashSafe(uint256 a) public view returns (bytes32) {\n"
    "        return keccak256(abi.encode(a, nonce, block.chainid));\n"
    "    }\n"
    "    function permitVerify(uint256 b) public pure returns (bytes32) {\n"
    "        return keccak256(abi.encodePacked(b));\n"
    "    }\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Secure.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_BOTH}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_CHAINID}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_NONCE}},
    {"input": {"file_path": "Skip.sol", "solidity_code": _NAME_NOT_MATCHED}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_BOTH, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_BOTH},
     "env": {"PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE": "false"}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _MISSING_BOTH},
     "env": {"PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE": "true"}},
]
