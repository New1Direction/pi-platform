"""Parity spec for PiZKProofPublicInputVerif.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKProofPublicInputVerif"

_mod = load_py_agent("pi_zk_proof_public_input_verif.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKProofPublicInputVerif()
    out = agent.audit_public_input(_mod.ZKProofPublicInputVerifInput(**data))
    return out.model_dump()


# A verifyProof function that validates its public inputs with require(input...).
_SECURE_REQUIRE = "\n".join(
    [
        "function verifyProof(uint[2] a, uint[] input) public returns (bool) {",
        "    require(input[0] == expectedRoot);",
        "    return verifier.verify(a, input);",
        "}",
    ]
)

# A verifyProof function that uses input but never constrains it -> vulnerable.
_VULN_UNCHECKED = "\n".join(
    [
        "function verifyProof(uint[2] a, uint[] input) public returns (bool) {",
        "    bool ok = verifier.verify(a, input);",
        "    return ok;",
        "}",
    ]
)

# verifyZK variant flagged (covers the 'verifyzk' name branch).
_VULN_VERIFYZK = "\n".join(
    [
        "function verifyZK(bytes proof, uint[] input) external returns (bool) {",
        "    uint n = input.length;",
        "    return zk.check(proof, n);",
        "}",
    ]
)

# Uses publicInput keyword and validates via if(...) -> secure.
_SECURE_IF = "\n".join(
    [
        "function verifyProofWithState(bytes proof, uint[] publicInput) public {",
        "    if (publicInput[0] != stored) revert();",
        "    zk.run(proof, publicInput);",
        "}",
    ]
)

# Multiple functions: one secure verifier, one vulnerable verifier, and an
# unrelated function. Exercises the multi-block scan / lookahead replacement.
_MULTI = "\n".join(
    [
        "function deposit(uint amount) external {",
        "    balances[msg.sender] += amount;",
        "}",
        "function verifyProof(uint[2] a, uint[] input) public returns (bool) {",
        "    return verifier.verify(a, input);",
        "}",
        "function verifyProofChecked(uint[2] b, uint[] input) public returns (bool) {",
        "    require(input[0] == root);",
        "    return verifier.verify(b, input);",
        "}",
    ]
)

# A verifier function that mentions neither 'input' nor 'publicInput' in its
# body -> not flagged even though name matches.
_NO_INPUT_BODY = "\n".join(
    [
        "function verifyProof(uint[2] a, uint[] data) public returns (bool) {",
        "    return verifier.verify(a, data);",
        "}",
    ]
)

# assert(input...) path -> validated, secure.
_SECURE_ASSERT = "\n".join(
    [
        "function verifyZK(bytes proof, uint[] input) external {",
        "    assert(input.length == 4);",
        "    zk.run(proof, input);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "V.sol", "solidity_code": _SECURE_REQUIRE}},
    {"input": {"file_path": "V.sol", "solidity_code": _VULN_UNCHECKED}},
    {"input": {"file_path": "V.sol", "solidity_code": _VULN_VERIFYZK}},
    {"input": {"file_path": "V.sol", "solidity_code": _SECURE_IF}},
    {"input": {"file_path": "V.sol", "solidity_code": _SECURE_ASSERT}},
    {"input": {"file_path": "V.sol", "solidity_code": _NO_INPUT_BODY}},
    {"input": {"file_path": "V.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "V.sol", "solidity_code": ""}},
    {"input": {"file_path": "V.sol", "solidity_code": _VULN_UNCHECKED, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "V.sol", "solidity_code": _VULN_UNCHECKED},
     "env": {"PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE": "false"}},
    {"input": {"file_path": "V.sol", "solidity_code": _VULN_UNCHECKED},
     "env": {"PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE": "true"}},
]
