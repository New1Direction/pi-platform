"""Parity spec for PiSemanticCommitMessageLinter.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSemanticCommitMessageLinter"

_mod = load_py_agent("pi_semantic_commit_message_linter.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSemanticCommitMessageLinter()
    out = agent.audit_commit_message(_mod.CommitLinterInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean / passing: type(scope): description
    {"input": {"commit_message": "feat(parser): add streaming tokenizer"}},
    # clean / passing: type: description (no scope), with breaking-change marker
    {"input": {"commit_message": "fix!: resolve critical auth bypass"}},
    # bad format: not a conventional commit at all
    {"input": {"commit_message": "added a new thing to the parser"}},
    # bad format: type not in allowed list
    {"input": {"commit_message": "feature(api): add endpoint"}},
    # matches format but description too short (< 5 chars)
    {"input": {"commit_message": "fix: bug"}},
    # empty after strip -> "cannot be empty" path
    {"input": {"commit_message": "   "}},
    # leading/trailing whitespace gets stripped, still valid
    {"input": {"commit_message": "  chore(deps): bump pydantic to 2.6  "}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"commit_message": "added a new thing to the parser"},
     "env": {"PI_COMMIT_LINTER_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"commit_message": "added a new thing to the parser"},
     "env": {"PI_COMMIT_LINTER_STRICT_MODE": "true"}},
]
