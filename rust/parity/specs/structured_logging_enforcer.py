"""Parity spec for PiStructuredLoggingEnforcer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiStructuredLoggingEnforcer"

_mod = load_py_agent("pi_structured_logging_enforcer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiStructuredLoggingEnforcer()
    out = agent.enforce_structured_logging(_mod.StructuredLoggingInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "import logging",
        "logger = logging.getLogger(__name__)",
        "logger.info('structured event', extra={'k': 'v'})",
    ]
)
_SINGLE_PRINT = "print('hello world')"
_INDENTED_PRINT = "def f():\n    print('debug')\n    return 1"
_COMMENTED_PRINT = "# print('this is a comment, not flagged')\nlogger.info('ok')"
_SPACED_PRINT = "print ('weird spacing still matches')"
_NOT_PRINT = "fprint('not a print')\nblueprint(x)\nsprint()"
_MANY_PRINTS = "\n".join(["print(%d)" % i for i in range(8)])
_MIXED = "\n".join(
    [
        "import sys",
        "print('first')",
        "logger.info('structured')",
        "    print('second indented')",
        "# print('commented out')",
        "x = blueprint()",
    ]
)

SAMPLES = [
    # clean / passing input
    {"input": {"file_path": "clean.py", "code_content": _CLEAN}},
    # single print -> one finding, score 85.0, NON_COMPLIANT
    {"input": {"file_path": "p.py", "code_content": _SINGLE_PRINT}},
    # indented print still flagged
    {"input": {"file_path": "p.py", "code_content": _INDENTED_PRINT}},
    # commented-out print is ignored (line.strip().startswith("#"))
    {"input": {"file_path": "p.py", "code_content": _COMMENTED_PRINT}},
    # 'print (' with whitespace before paren still matches \bprint\s*\(
    {"input": {"file_path": "p.py", "code_content": _SPACED_PRINT}},
    # tokens that contain 'print' as a substring but not the word -> not flagged
    {"input": {"file_path": "p.py", "code_content": _NOT_PRINT}},
    # many prints -> score floors at 0.0
    {"input": {"file_path": "p.py", "code_content": _MANY_PRINTS}},
    # mixed content exercising flag + comment + non-match
    {"input": {"file_path": "p.py", "code_content": _MIXED}},
    # empty / edge input
    {"input": {"file_path": "empty.py", "code_content": ""}},
]
