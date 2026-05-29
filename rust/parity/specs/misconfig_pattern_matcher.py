"""Parity spec for PiMisconfigPatternMatcher.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiMisconfigPatternMatcher"

_mod = load_py_agent("pi_misconfig_pattern_matcher.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiMisconfigPatternMatcher()
    out = agent.match_config(_mod.ConfigInput(**data))
    return out.model_dump()


_CLEAN = "host = localhost\nport = 8080\ntimeout = 30"
# Hardcoded password path: password key + admin/test/root keyword -> 85.0
_HARDCODED_PW = "ADMIN_PASSWORD=hunter2\nuser=ADMIN"
# password key present but no admin/test/root keyword -> NOT flagged
_PW_NO_KEYWORD = "service_password=secret\nuser=service"
# Debug mode path -> 60.0
_DEBUG = "log_level=info\ndebug=true"
# Insecure DB path -> 90.0
_EMPTY_PW = "[mysqld]\nallow_empty_password=true"
# Multiple patterns at once: max() keeps the highest risk (90.0)
_MULTI = "\n".join(
    [
        "password: rootpw",
        "test_mode: true",
        "empty_password=true",
    ]
)

SAMPLES = [
    # clean / passing input
    {"input": {"config_content": _CLEAN}},
    # hardcoded admin password -> risk 85, strict default rejects
    {"input": {"config_content": _HARDCODED_PW}},
    # password key without admin/test/root -> no match, secure
    {"input": {"config_content": _PW_NO_KEYWORD}},
    # debug mode enabled -> risk 60
    {"input": {"config_content": _DEBUG}},
    # insecure DB empty password -> risk 90
    {"input": {"config_content": _EMPTY_PW}},
    # multiple patterns -> matched_patterns ordering + max risk
    {"input": {"config_content": _MULTI}},
    # empty/edge input
    {"input": {"config_content": ""}},
    # non-strict env -> WARN path, is_secure stays True even at risk 90
    {"input": {"config_content": _EMPTY_PW},
     "env": {"PI_CONFIG_STRICT_MODE": "false"}},
    # explicit strict env -> rejected
    {"input": {"config_content": _EMPTY_PW},
     "env": {"PI_CONFIG_STRICT_MODE": "true"}},
]
