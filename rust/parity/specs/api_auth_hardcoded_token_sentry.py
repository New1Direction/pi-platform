"""Parity spec for PiApiAuthHardcodedTokenSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiApiAuthHardcodedTokenSentry"

_mod = load_py_agent("pi_api_auth_hardcoded_token_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiApiAuthHardcodedTokenSentry()
    out = agent.audit_hardcoded_tokens(_mod.ApiAuthHardcodedTokenInput(**data))
    return out.model_dump()


# Clean code: no credential assignments at all.
_SECURE = "user = get_user()\nresult = compute(user)"

# A plain hardcoded token (>=16 allowed chars).
_TOKEN = 'token = "abcdefghij1234567890"'

# api_key with a colon separator (e.g. YAML-ish) and IGNORECASE name.
_API_KEY = 'API_KEY: "STRIPE_LIVE_KEY_SCRUBBED"'

# bearer credential.
_BEARER = "bearer = 'Bearer_aaaabbbbccccdddd'"

# Value that hits an excluded placeholder ("os.getenv") -> NOT flagged.
_EXCLUDED = 'client_secret = "os_getenv_PLACEHOLDER_VALUE"'

# Excluded via "config" substring -> NOT flagged.
_EXCLUDED_CONFIG = 'api_token = "config_default_token_value"'

# Comment lines are skipped (both # and //).
_COMMENTS = '# token = "abcdefghij1234567890"\n// api_key = "abcdefghij1234567890"'

# Too-short value (< 16 chars) -> regex does not match -> secure.
_SHORT = 'token = "short_one"'

# Multi-line mix: one real finding plus a commented/excluded line.
_MULTI = "\n".join(
    [
        "import os",
        'real = token = "REALSECRET0123456789abc"',
        '# token = "abcdefghij1234567890"',
        'safe = api_key = "process.env.MY_KEY_FALLBACK"',
        'another_api_token = "ZZZZyyyyXXXX99998888"',
    ]
)

SAMPLES = [
    {"input": {"file_path": "a.py", "code_content": _SECURE}},
    {"input": {"file_path": "a.py", "code_content": _TOKEN}},
    {"input": {"file_path": "a.yaml", "code_content": _API_KEY}},
    {"input": {"file_path": "a.py", "code_content": _BEARER}},
    {"input": {"file_path": "a.py", "code_content": _EXCLUDED}},
    {"input": {"file_path": "a.py", "code_content": _EXCLUDED_CONFIG}},
    {"input": {"file_path": "a.py", "code_content": _COMMENTS}},
    {"input": {"file_path": "a.py", "code_content": _SHORT}},
    {"input": {"file_path": "a.py", "code_content": _MULTI}},
    {"input": {"file_path": "a.py", "code_content": ""}},
    {"input": {"file_path": "a.py", "code_content": _TOKEN, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.py", "code_content": _TOKEN},
     "env": {"PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.py", "code_content": _TOKEN},
     "env": {"PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE": "true"}},
]
