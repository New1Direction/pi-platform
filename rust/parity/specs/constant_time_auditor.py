"""Parity spec for PiConstantTimeAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiConstantTimeAuditor"

_mod = load_py_agent("pi_constant_time_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiConstantTimeAuditor()
    out = agent.audit_constant_time(_mod.ConstantTimeInput(**data))
    return out.model_dump()


# Clean: secret appears but no division/modulo and no if/while branch on it.
_CLEAN = "\n".join(
    [
        "x = a + b",
        "result = priv_key + nonce",
        "return result",
    ]
)
# Division / modulo on a secret.
_DIV = "remainder = priv_key % modulus"
# Branch condition on a secret (if).
_IF = "if (secret_bit == 1): do_thing()"
# Loop condition on a secret (while).
_WHILE = "    while (priv_key > threshold):  step()  "
# Both a division and a branch on the same secret across lines.
_MULTI = "\n".join(
    [
        "import crypto",
        "ratio = priv_key / divisor",
        "if (priv_key > 0): branch()",
        "safe = pub_key + 1",
        "comment = 'priv_key is mentioned but no op here'",
    ]
)

SAMPLES = [
    # clean passing input (secret present, no risky ops)
    {"input": {"file_path": "a.py", "source_code": _CLEAN,
               "secrets_context": ["priv_key", "nonce"]}},
    # division/modulo path
    {"input": {"file_path": "a.py", "source_code": _DIV,
               "secrets_context": ["priv_key"]}},
    # if-branch path
    {"input": {"file_path": "a.py", "source_code": _IF,
               "secrets_context": ["secret_bit"]}},
    # while-loop path (also has leading/trailing whitespace to exercise strip)
    {"input": {"file_path": "a.py", "source_code": _WHILE,
               "secrets_context": ["priv_key"]}},
    # multi-line with several flagged + clean lines
    {"input": {"file_path": "a.py", "source_code": _MULTI,
               "secrets_context": ["priv_key"]}},
    # empty source code edge case
    {"input": {"file_path": "a.py", "source_code": "",
               "secrets_context": ["priv_key"]}},
    # no secrets at all -> nothing flagged even with risky ops
    {"input": {"file_path": "a.py",
               "source_code": "if (priv_key > 0): x = priv_key / 2",
               "secrets_context": []}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.py", "source_code": _DIV,
               "secrets_context": ["priv_key"]},
     "env": {"PI_CONSTANT_TIME_STRICT_MODE": "false"}},
    # strict env explicitly -> REJECTED path
    {"input": {"file_path": "a.py", "source_code": _DIV,
               "secrets_context": ["priv_key"]},
     "env": {"PI_CONSTANT_TIME_STRICT_MODE": "true"}},
]
