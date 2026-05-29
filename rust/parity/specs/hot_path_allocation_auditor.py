"""Parity spec for PiHotPathAllocationAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiHotPathAllocationAuditor"

_mod = load_py_agent("pi_hot_path_allocation_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiHotPathAllocationAuditor()
    out = agent.audit_hot_path(_mod.HotPathAllocationInput(**data))
    return out.model_dump()


_CLEAN = "var x = ComputeSpan(input);"
_TOLOWER = "var y = s.ToLower();"
_SUBSTRING = "var z = name.Substring(0, 4);"
_NEW_DICT = "var d = new   Dictionary<string, int>();"
_REGEX = "var r = new Regex(pattern);"
_MULTI = "\n".join(
    [
        "public string Norm(string s) {",
        "    var lowered = s.ToLower();",
        "    var slice = s.Substring(0, 2);",
        "    var map = new Dictionary<string, int>();",
        "    var rx = new Regex(@\"\\d+\");",
        "    return lowered;",
        "}",
    ]
)

SAMPLES = [
    # Clean code, scanning all lines -> PASSED.
    {"input": {"file_path": "a.cs", "source_code": _CLEAN}},
    # Each distinct anti-pattern, scanning all lines.
    {"input": {"file_path": "a.cs", "source_code": _TOLOWER}},
    {"input": {"file_path": "a.cs", "source_code": _SUBSTRING}},
    {"input": {"file_path": "a.cs", "source_code": _NEW_DICT}},
    {"input": {"file_path": "a.cs", "source_code": _REGEX}},
    # Multi-line file with several anti-patterns, scanning all lines.
    {"input": {"file_path": "a.cs", "source_code": _MULTI}},
    # Same multi-line file, but only line 3 (the Substring line) is a hot path.
    {"input": {"file_path": "a.cs", "source_code": _MULTI, "hot_path_lines": [3]}},
    # Hot line points at a clean line -> nothing flagged.
    {"input": {"file_path": "a.cs", "source_code": _MULTI, "hot_path_lines": [1, 6]}},
    # Empty/edge input.
    {"input": {"file_path": "a.cs", "source_code": ""}},
    # Env var exercising both strict-mode branches on a flagged input.
    {"input": {"file_path": "a.cs", "source_code": _TOLOWER},
     "env": {"PI_PERF_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.cs", "source_code": _TOLOWER},
     "env": {"PI_PERF_STRICT_MODE": "true"}},
]
