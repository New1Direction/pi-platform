"""Parity spec for PiApiAuthJWTNoneAlgorithmSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiApiAuthJWTNoneAlgorithmSentry"

_mod = load_py_agent("pi_api_auth_jwt_none_algorithm_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiApiAuthJWTNoneAlgorithmSentry()
    out = agent.audit_jwt_none_algorithm(_mod.ApiAuthJWTNoneAlgorithmInput(**data))
    return out.model_dump()


_SECURE = "token = jwt.decode(t, key, algorithms=['HS256'])"
_NONE = "jwt.decode(token, key, algorithms=['none'])"
_NOALG = "data = jwt.decode(token, secret)"
_VERIFY_OFF = "jwt.verify(token, verify=False)"
_MULTI = "\n".join(
    [
        "import jwt",
        "ok = jwt.decode(t, k, algorithms=['HS256'])",
        "bad = jwt.decode(t, k)",
        "    weird = jwt.verify(x, verify=false)  ",
        "comment = 'jwt.decode is fine in a string with algorithms'",
    ]
)

SAMPLES = [
    {"input": {"file_path": "a.py", "code_content": _SECURE}},
    {"input": {"file_path": "a.py", "code_content": _NONE}},
    {"input": {"file_path": "a.py", "code_content": _NOALG}},
    {"input": {"file_path": "a.py", "code_content": _VERIFY_OFF}},
    {"input": {"file_path": "a.py", "code_content": _MULTI}},
    {"input": {"file_path": "a.py", "code_content": ""}},
    {"input": {"file_path": "a.py", "code_content": _NONE, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.py", "code_content": _NOALG},
     "env": {"PI_API_AUTH_JWT_NONE_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.py", "code_content": _NOALG},
     "env": {"PI_API_AUTH_JWT_NONE_STRICT_MODE": "true"}},
]
