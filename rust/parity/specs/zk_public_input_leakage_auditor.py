"""Parity spec for PiZKPublicInputLeakageAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKPublicInputLeakageAuditor"

_mod = load_py_agent("pi_zk_public_input_leakage_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKPublicInputLeakageAuditor()
    out = agent.audit_public_input_leakage(_mod.ZKPublicInputLeakageInput(**data))
    return out.model_dump()


# Clean circuit: a template with no 'public' marker and no leaking assignment.
_CLEAN = "template Adder(n) { signal input a; signal output b; b <== a; }"

# Leakage via <== where a public-named signal receives a secret-named signal.
_LEAK_PUB = (
    "template Leaky(n) {\n"
    "    signal public pubOut;\n"
    "    pubOut <== secretWitness;\n"
    "}"
)

# Leakage via 'out' signal receiving a 'priv' signal, using the '=' operator,
# with 'public' appearing in the parameter list.
_LEAK_OUT = "template T(public m) { outVal = privData; }"

# Leakage via the <-- operator.
_LEAK_ASSIGN = (
    "template Mixer(k) {\n"
    "    signal public commitment;\n"
    "    publicHash <-- privSecret;\n"
    "}"
)

# Multiple templates in one file: first clean, second leaks twice.
_MULTI = "\n".join(
    [
        "template Clean(n) { signal output y; y <== x; }",
        "template Bad(public p) {",
        "    pubA <== secretOne;",
        "    outB = privTwo;",
        "}",
    ]
)

# 'public' present in body but no leaking assignment -> still secure.
_PUBLIC_NO_LEAK = "template Pub(n) { signal public z; z <== a; }"

SAMPLES = [
    {"input": {"file_path": "c.circom", "circom_code": _CLEAN}},
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_PUB}},
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_OUT}},
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_ASSIGN}},
    {"input": {"file_path": "c.circom", "circom_code": _MULTI}},
    {"input": {"file_path": "c.circom", "circom_code": _PUBLIC_NO_LEAK}},
    {"input": {"file_path": "c.circom", "circom_code": ""}},
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_PUB, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_OUT},
     "env": {"PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE": "false"}},
    {"input": {"file_path": "c.circom", "circom_code": _LEAK_OUT},
     "env": {"PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE": "true"}},
]
