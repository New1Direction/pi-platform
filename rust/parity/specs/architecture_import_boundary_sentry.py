"""Parity spec for PiArchitectureImportBoundarySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiArchitectureImportBoundarySentry"

_mod = load_py_agent("pi_architecture_import_boundary_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiArchitectureImportBoundarySentry()
    out = agent.check_import_boundaries(_mod.ImportBoundaryInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "import os",
        "from typing import List, Dict",
        "import logging",
    ]
)
_VIOLATION = "\n".join(
    [
        "import os",
        "from infrastructure.db import session",
        "import logging",
    ]
)
_MULTI = "\n".join(
    [
        "import os",
        "from infrastructure.db import session",
        "import infrastructure.cache as cache",
        "from domain.model import Order",
        "    import infrastructure.queue",  # indented import still matches ^\s*
    ]
)
_SLASH = "import a.b.c.d"
_FROM_ONLY = "from a.b import thing"
_COMMENT = "\n".join(
    [
        "# import infrastructure.db  -- comment, leading '#' breaks the anchor",
        "x = 'from infrastructure import y'  # string literal, not an import line",
    ]
)

SAMPLES = [
    # clean / passing input: file matches a rule but no forbidden imports present
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _CLEAN,
        "forbidden_mappings": {"src/domain": ["infrastructure", "src.api"]},
    }},
    # single 'from ... import' violation
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _VIOLATION,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }},
    # multiple violations across both 'import' and 'from' forms, plus a clean import
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _MULTI,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }},
    # file_path does NOT match any rule key -> no scanning, secure
    {"input": {
        "file_path": "src/api/handler.py",
        "code_content": _VIOLATION,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }},
    # slash-normalization path: forbidden "a/b" -> "a.b" matches module "a.b.c.d"
    {"input": {
        "file_path": "x/y.py",
        "code_content": _SLASH,
        "forbidden_mappings": {"x/y": ["a/b"]},
    }},
    # multiple matching rule keys (insertion order matters for violation ordering)
    {"input": {
        "file_path": "src/domain/service.py",
        "code_content": _FROM_ONLY,
        "forbidden_mappings": {"src/domain": ["a.b"], "service": ["a"]},
    }},
    # comments and string literals must NOT be flagged (anchor / no import keyword)
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _COMMENT,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }},
    # empty / edge input: empty code, empty mappings
    {"input": {
        "file_path": "",
        "code_content": "",
        "forbidden_mappings": {},
    }},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _VIOLATION,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }, "env": {"PI_IMPORT_BOUNDARY_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {
        "file_path": "src/domain/order.py",
        "code_content": _VIOLATION,
        "forbidden_mappings": {"src/domain": ["infrastructure"]},
    }, "env": {"PI_IMPORT_BOUNDARY_STRICT_MODE": "true"}},
]
