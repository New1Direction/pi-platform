"""Parity spec for PiZKProofForgingValidationSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKProofForgingValidationSentry"

_mod = load_py_agent("pi_zk_proof_forging_validation_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKProofForgingValidationSentry()
    out = agent.audit_proof_forging(_mod.ZKProofForgingValidationInput(**data))
    return out.model_dump()


# A verifier template that DOES commit to a hash -> secure.
_SECURE_HASH = "template ProofVerify(n) {\n    signal input pub;\n    component h = Sha256();\n    pub === h.out;\n}"
# A verifier template that references a commitment -> secure.
_SECURE_COMMITMENT = "template VerifyMembership() {\n    signal input commitment;\n    commitment === root;\n}"
# Verifier named with 'verify', no hash/commitment/sha -> vulnerable.
_VULN_VERIFY = "template ProofVerify(levels) {\n    signal input a;\n    signal output ok;\n    ok <== a;\n}"
# Template named with 'proof', no hash/commitment/sha -> vulnerable.
_VULN_PROOF = "template GenProofChecker(k) {\n    signal input x;\n    signal output y;\n    y <== x * x;\n}"
# Non-verifier template (no 'verify'/'proof' in name) -> ignored, secure.
_NON_VERIFIER = "template Adder(n) {\n    signal input a;\n    signal input b;\n    signal output c;\n    c <== a + b;\n}"
# Mixed: one secure verifier (has hash) + one vulnerable verifier + a non-verifier.
_MIXED = "\n".join(
    [
        "template Adder(n) { signal input a; signal output b; b <== a; }",
        "template ProofVerify(n) { signal input p; signal output o; o <== p; }",
        "template HashVerify(n) { signal input hash; hash === root; }",
    ]
)
# No templates at all.
_NO_TEMPLATES = "pragma circom 2.0.0;\n// just a comment, no templates here\nfunction foo() { return 1; }"

SAMPLES = [
    # clean / passing: verifier guarded by a hash
    {"input": {"file_path": "c.circom", "circom_code": _SECURE_HASH}},
    # clean / passing: verifier guarded by a commitment
    {"input": {"file_path": "c.circom", "circom_code": _SECURE_COMMITMENT}},
    # vulnerable path via 'verify' in template name
    {"input": {"file_path": "c.circom", "circom_code": _VULN_VERIFY}},
    # vulnerable path via 'proof' in template name
    {"input": {"file_path": "c.circom", "circom_code": _VULN_PROOF}},
    # non-verifier template is ignored -> secure
    {"input": {"file_path": "c.circom", "circom_code": _NON_VERIFIER}},
    # mixed: vulnerable verifier flagged, secure + non-verifier untouched
    {"input": {"file_path": "c.circom", "circom_code": _MIXED}},
    # no templates -> secure
    {"input": {"file_path": "c.circom", "circom_code": _NO_TEMPLATES}},
    # empty / edge input
    {"input": {"file_path": "c.circom", "circom_code": ""}},
    # check_level override (non-default value)
    {"input": {"file_path": "c.circom", "circom_code": _VULN_VERIFY, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "c.circom", "circom_code": _VULN_VERIFY},
     "env": {"PI_ZK_PROOF_FORGING_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "c.circom", "circom_code": _VULN_VERIFY},
     "env": {"PI_ZK_PROOF_FORGING_STRICT_MODE": "true"}},
]
