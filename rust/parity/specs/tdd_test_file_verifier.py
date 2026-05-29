"""Parity spec for PiTddTestFileVerifier.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTddTestFileVerifier"

_mod = load_py_agent("pi_tdd_test_file_verifier.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTddTestFileVerifier()
    out = agent.verify_test_files(_mod.TddTestFileInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean/passing: impl file with a matching test file present
    {"input": {"modified_files": ["src/calc.py", "tests/test_calc.py"]}},
    # impl file with NO matching test -> flagged (strict default -> REJECTED)
    {"input": {"modified_files": ["src/widget.py"]}},
    # .ts impl with matching .test.ts file present
    {"input": {"modified_files": ["src/api.ts", "src/api.test.ts"]}},
    # .tsx impl, only the double-replaced test name would match exactly; stem
    # "component" still matches via the split(".")[0] branch -> passing
    {"input": {"modified_files": ["src/component.tsx", "src/component.test.tsx"]}},
    # files that are all skipped (md/json/yml/no-slash/contains "test") -> PASSED
    {"input": {"modified_files": ["README.md", "config.json", "ci.yml", "main", "tests/foo_test.py"]}},
    # empty changeset -> nothing to flag -> PASSED
    {"input": {"modified_files": []}},
    # multiple impls, one missing its test -> only the missing one flagged
    {"input": {"modified_files": ["src/a.py", "tests/test_a.py", "src/b.py"]}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"modified_files": ["src/widget.py"]},
     "env": {"PI_TDD_FILE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED
    {"input": {"modified_files": ["src/widget.py"]},
     "env": {"PI_TDD_FILE_STRICT_MODE": "true"}},
]
