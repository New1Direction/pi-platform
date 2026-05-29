"""Parity spec for PiDepreciationScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDepreciationScanner"

_mod = load_py_agent("pi_depreciation_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDepreciationScanner()
    out = agent.scan_depreciation(_mod.DepreciationInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "import os",
        "def handler():",
        "    return safe_call(value)",
    ]
)
_FLAGGED = "\n".join(
    [
        "import os",
        "result = old_api(payload)",
    ]
)
_DOTTED = "\n".join(
    [
        "a = os.system(cmd)",
        "b = os.system(other)",
    ]
)
# Word-boundary guard: pattern must NOT match as a substring of a larger token.
_SUBSTRING = "x = old_apifoo() + legacy_handler_v2()"
# Multiple distinct patterns flagged across the same and different lines.
_MULTI = "\n".join(
    [
        "import imp",
        "data = imp.load_source('m', path)",
        "thread.start_new_thread(worker, ())",
        "ok = modern_call()",
    ]
)
# Pattern containing regex-special chars (escaped by re.escape) and a space.
_SPECIAL = "do the legacy call now"

SAMPLES = [
    # 1. Clean code, nothing deprecated -> PASSED, secure.
    {"input": {"file_path": "a.py", "code_content": _CLEAN,
               "deprecated_patterns": ["old_api", "imp", "thread.start_new_thread"]}},
    # 2. Single deprecated symbol on one line -> REJECTED (default strict).
    {"input": {"file_path": "a.py", "code_content": _FLAGGED,
               "deprecated_patterns": ["old_api"]}},
    # 3. Same dotted symbol on two lines -> appended once per line.
    {"input": {"file_path": "a.py", "code_content": _DOTTED,
               "deprecated_patterns": ["os.system"]}},
    # 4. Word-boundary guard: substrings must not match.
    {"input": {"file_path": "a.py", "code_content": _SUBSTRING,
               "deprecated_patterns": ["old_api", "legacy_handler"]}},
    # 5. Multiple distinct deprecated symbols flagged.
    {"input": {"file_path": "a.py", "code_content": _MULTI,
               "deprecated_patterns": ["imp", "thread.start_new_thread", "deprecated_x"]}},
    # 6. Pattern with a space (re.escape -> "\ ").
    {"input": {"file_path": "a.py", "code_content": _SPECIAL,
               "deprecated_patterns": ["legacy call"]}},
    # 7. Empty code content, non-empty patterns -> nothing found, PASSED.
    {"input": {"file_path": "a.py", "code_content": "",
               "deprecated_patterns": ["old_api"]}},
    # 8. Empty pattern list -> nothing found, PASSED.
    {"input": {"file_path": "a.py", "code_content": _FLAGGED,
               "deprecated_patterns": []}},
    # 9. Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "a.py", "code_content": _FLAGGED,
               "deprecated_patterns": ["old_api"]},
     "env": {"PI_DEPRECIATION_STRICT_MODE": "false"}},
    # 10. Explicit strict env -> REJECTED path.
    {"input": {"file_path": "a.py", "code_content": _FLAGGED,
               "deprecated_patterns": ["old_api"]},
     "env": {"PI_DEPRECIATION_STRICT_MODE": "true"}},
]
