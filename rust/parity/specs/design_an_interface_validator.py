"""Parity spec for PiDesignAnInterfaceValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDesignAnInterfaceValidator"

_mod = load_py_agent("pi_design_an_interface_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDesignAnInterfaceValidator()
    out = agent.validate_interface(_mod.DesignAnInterfaceInput(**data))
    return out.model_dump()


# Clean: function with a return type, no class/interface lines.
_CLEAN = "\n".join(
    [
        "def add(a, b) -> int:",
        "    return a + b",
    ]
)

# Missing return type hint on a `def`.
_NO_RETURN = "def compute(value):\n    return value * 2"

# Class on line 2; previous line has no doc-block terminator -> flagged.
_CLASS_NO_DOC = "import os\nclass Widget:"

# TypeScript-style `interface ` keyword on line 2 -> flagged (no doc above).
_INTERFACE_NO_DOC = "import { x } from 'y'\ninterface Shape {"

# Class preceded by a JSDoc terminator `*/` -> NOT flagged.
_CLASS_JSDOC = "*/\nclass Documented:"

# Class preceded by a Python docstring marker `\"\"\"` -> NOT flagged.
_CLASS_DOCSTRING = '"""\nclass Annotated:'

# Mixed: a def missing return type AND a class missing docs, across lines.
_MIXED = "\n".join(
    [
        "x = 1",
        "def handler(req):",
        "    pass",
        "class Server:",
        "    pass",
    ]
)

# Class on the very first line: idx == 1, so the doc check is skipped entirely.
_CLASS_FIRST_LINE = "class Root:\n    pass"

SAMPLES = [
    {"input": {"interface_content": _CLEAN}},
    {"input": {"interface_content": _NO_RETURN}},
    {"input": {"interface_content": _CLASS_NO_DOC}},
    {"input": {"interface_content": _INTERFACE_NO_DOC}},
    {"input": {"interface_content": _CLASS_JSDOC}},
    {"input": {"interface_content": _CLASS_DOCSTRING}},
    {"input": {"interface_content": _MIXED}},
    {"input": {"interface_content": _CLASS_FIRST_LINE}},
    {"input": {"interface_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"interface_content": _MIXED},
     "env": {"PI_DESIGN_INTERFACE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"interface_content": _MIXED},
     "env": {"PI_DESIGN_INTERFACE_STRICT_MODE": "true"}},
]
