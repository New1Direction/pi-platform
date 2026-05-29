"""Parity spec for PiZoomOutSystemExplainer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZoomOutSystemExplainer"

_mod = load_py_agent("pi_zoom_out_system_explainer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZoomOutSystemExplainer()
    out = agent.explain_system(_mod.ZoomOutInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "import os",
        "import re",
        "from typing import List",
        "from pydantic import BaseModel, Field",
    ]
)

# Leading whitespace (\s*) + duplicate imports that must be deduped.
_INDENTED_DUP = "\n".join(
    [
        "    import os",
        "import os",
        "from os import path",
        "from . import sibling",
        "import a.b.c",
    ]
)

# 16 distinct imports -> len >= 15 -> not secure -> REJECTED in strict mode.
_TOO_MANY = "\n".join([f"import pkg{i}" for i in range(16)])

# Exactly 14 distinct imports -> len < 15 -> still secure.
_FOURTEEN = "\n".join([f"import pkg{i}" for i in range(14)])

# Lines that must NOT match the import regex (mid-line / string / comment).
_NON_MATCH = "\n".join(
    [
        "x = 1  # import os",
        "result = do_import_things()",
        "text = 'from foo import bar'",
        "from import",  # malformed, group(2) requires a package name
    ]
)

SAMPLES = [
    {"input": {"file_path": "clean.py", "code_content": _CLEAN}},
    {"input": {"file_path": "dup.py", "code_content": _INDENTED_DUP}},
    {"input": {"file_path": "fourteen.py", "code_content": _FOURTEEN}},
    {"input": {"file_path": "many.py", "code_content": _TOO_MANY}},
    {"input": {"file_path": "nonmatch.py", "code_content": _NON_MATCH}},
    {"input": {"file_path": "empty.py", "code_content": ""}},
    # too many imports + non-strict env -> WARN path, is_secure coerced True
    {"input": {"file_path": "many.py", "code_content": _TOO_MANY},
     "env": {"PI_ZOOM_OUT_STRICT_MODE": "false"}},
    # too many imports + strict env explicit -> REJECTED
    {"input": {"file_path": "many.py", "code_content": _TOO_MANY},
     "env": {"PI_ZOOM_OUT_STRICT_MODE": "true"}},
]
