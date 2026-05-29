"""Parity spec for PiDeadCodePruner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDeadCodePruner"

_mod = load_py_agent("pi_dead_code_pruner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDeadCodePruner()
    out = agent.prune_dead_code(_mod.DeadCodeInput(**data))
    return out.model_dump()


# Clean: import is used elsewhere -> no findings.
_CLEAN = "\n".join(
    [
        "import os",
        "print(os.getcwd())",
    ]
)

# Unused import via `import X`.
_UNUSED_IMPORT = "\n".join(
    [
        "import os",
        "print('hello world')",
    ]
)

# Unused import via `from pkg import name`.
_UNUSED_FROM = "\n".join(
    [
        "from collections import OrderedDict",
        "x = 1 + 2",
    ]
)

# Unreachable statement after a return at equal indentation.
_UNREACHABLE_RETURN = "\n".join(
    [
        "def f():",
        "    return 1",
        "    x = 2",
    ]
)

# Unreachable statement after a raise.
_UNREACHABLE_RAISE = "\n".join(
    [
        "def g():",
        "    raise ValueError('boom')",
        "    cleanup()",
    ]
)

# return followed by an excluded keyword (else) -> NOT flagged; import used.
_RETURN_THEN_ELSE = "\n".join(
    [
        "import sys",
        "def h(x):",
        "    if x:",
        "        return sys.argv",
        "    else:",
        "        return None",
    ]
)

SAMPLES = [
    {"input": {"file_path": "clean.py", "code_content": _CLEAN}},
    {"input": {"file_path": "u1.py", "code_content": _UNUSED_IMPORT}},
    {"input": {"file_path": "u2.py", "code_content": _UNUSED_FROM}},
    {"input": {"file_path": "r1.py", "code_content": _UNREACHABLE_RETURN}},
    {"input": {"file_path": "r2.py", "code_content": _UNREACHABLE_RAISE}},
    {"input": {"file_path": "ok.py", "code_content": _RETURN_THEN_ELSE}},
    # empty / edge input
    {"input": {"file_path": "empty.py", "code_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "u1.py", "code_content": _UNUSED_IMPORT},
     "env": {"PI_DEAD_CODE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "u1.py", "code_content": _UNUSED_IMPORT},
     "env": {"PI_DEAD_CODE_STRICT_MODE": "true"}},
]
