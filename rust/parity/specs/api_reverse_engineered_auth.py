"""Parity spec for PiApiReverseEngineeredAuth.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiApiReverseEngineeredAuth"

_mod = load_py_agent("pi_api_reverse_engineered_auth.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiApiReverseEngineeredAuth()
    out = agent.audit_reverse_auth(_mod.ApiReverseEngineeredAuthInput(**data))
    return out.model_dump()


# Clean / passing input: variable used as the signing key, not a hardcoded literal.
_SECURE = "const t = jwt.sign(payload, privateKeyVariable)"
# Hardcoded JWT signing secret (alternative 1 of the regex).
_HARDCODED_SECRET = 'const t = jwt.sign(payload, "mysecret")'
# jwt.sign secret spanning a newline (exercises [\s\S]* across lines).
_HARDCODED_MULTILINE = 'jwt.sign(payload,\n  "supersecretkey")'
# algorithm: 'none' (alternative 2 of the regex).
_ALG_NONE = "options = { algorithm: 'none' }"
# Hardcoded "Authorization: Bearer ey..." header (alternative 3 of the regex).
_HARDCODED_BEARER = 'headers = { "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9" }'
# Bearer header without surrounding quotes on the key (optional quotes branch).
_BEARER_NOQUOTE = 'Authorization: "Bearer eyABCdef"'

SAMPLES = [
    {"input": {"file_path": "client.js", "auth_code": _SECURE}},
    {"input": {"file_path": "client.js", "auth_code": _HARDCODED_SECRET}},
    {"input": {"file_path": "client.js", "auth_code": _HARDCODED_MULTILINE}},
    {"input": {"file_path": "config.yaml", "auth_code": _ALG_NONE}},
    {"input": {"file_path": "client.js", "auth_code": _HARDCODED_BEARER}},
    {"input": {"file_path": "client.js", "auth_code": _BEARER_NOQUOTE}},
    # empty / edge input -> no findings, PASSED.
    {"input": {"file_path": "empty.txt", "auth_code": ""}},
    # check_level is accepted but unused by the logic.
    {"input": {"file_path": "client.js", "auth_code": _ALG_NONE, "check_level": "LENIENT"}},
    # strict env -> REJECTED path.
    {"input": {"file_path": "client.js", "auth_code": _HARDCODED_SECRET},
     "env": {"PI_API_REVERSE_ENGINEER_AUTH_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "client.js", "auth_code": _HARDCODED_SECRET},
     "env": {"PI_API_REVERSE_ENGINEER_AUTH_STRICT_MODE": "false"}},
]
