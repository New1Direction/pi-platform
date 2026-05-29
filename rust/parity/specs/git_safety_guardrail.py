"""Parity spec for PiGitSafetyGuardrail.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGitSafetyGuardrail"

_mod = load_py_agent("pi_git_safety_guardrail.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGitSafetyGuardrail()
    out = agent.check_git_safety(_mod.GitSafetyInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean / passing command
    {"input": {"command_string": "git status"}},
    # push --force (long flag)
    {"input": {"command_string": "git push origin main --force"}},
    # push -f (short flag)
    {"input": {"command_string": "git push origin main -f"}},
    # branch -D
    {"input": {"command_string": "git branch -D feature/old"}},
    # reset --hard
    {"input": {"command_string": "git reset --hard HEAD~3"}},
    # multiple dangerous patterns chained with whitespace/ampersands
    {"input": {"command_string": "git push -f && git reset --hard origin/main"}},
    # mixed case exercising IGNORECASE
    {"input": {"command_string": "GIT PUSH --FORCE"}},
    # empty / edge input (becomes "" after strip)
    {"input": {"command_string": "   "}},
    # near-miss: contains -f but not a force push of git (no 'push' token)
    {"input": {"command_string": "git config -f .gitconfig user.name x"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"command_string": "git push origin main --force"},
     "env": {"PI_GIT_SAFETY_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"command_string": "git reset --hard"},
     "env": {"PI_GIT_SAFETY_STRICT_MODE": "true"}},
]
