"""Parity spec for PiSelfHealingPatchAgent.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSelfHealingPatchAgent"

_mod = load_py_agent("pi_self_healing_patch_agent.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSelfHealingPatchAgent()
    out = agent.heal_vulnerabilities(_mod.SelfHealingInput(**data))
    return out.model_dump()


# --- requirements.txt style dependency pinning ---------------------------------
_REQ_PINNED = "\n".join(
    [
        "# project requirements",
        "flask>=1.0",
        "requests",
        "lodash~=3.0",
        "",
    ]
)

# --- package.json style dependency pinning -------------------------------------
_PKG_JSON = "\n".join(
    [
        "{",
        '  "dependencies": {',
        '    "react": "^17.0.0",',
        '    "lodash": "*"',
        "  }",
        "}",
    ]
)

# --- dangerous eval remediation ------------------------------------------------
_EVAL = "\n".join(
    [
        "def handler(payload):",
        "    result = eval(payload)",
        "    return result",
    ]
)

# --- mixed / unmatched line (comment + blank are passed through) ---------------
_MIXED = "\n".join(
    [
        "# comment line",
        "",
        "===garbage===",
        "pytest>=2.0",
    ]
)

SAMPLES = [
    # 1. UNPINNED_DEP requirements.txt: pin flask + requests + lodash
    {"input": {"file_path": "requirements.txt", "source_code": _REQ_PINNED,
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [1, 2, 3, 4]}},
    # 2. UNPINNED_DEP package.json: pin react + lodash JSON entries
    {"input": {"file_path": "package.json", "source_code": _PKG_JSON,
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [3, 4]}},
    # 3. DANGEROUS_EVAL: replace eval line with pass placeholder
    {"input": {"file_path": "handler.py", "source_code": _EVAL,
               "vulnerability_type": "DANGEROUS_EVAL", "vulnerable_lines": [2]}},
    # 4. lowercase vulnerability_type -> upper() normalizes it
    {"input": {"file_path": "requirements.txt", "source_code": "flask\nrequests",
               "vulnerability_type": "unpinned_dep", "vulnerable_lines": [1, 2]}},
    # 5. mixed: comment/blank passthrough + unmatched garbage + a real pin
    {"input": {"file_path": "requirements.txt", "source_code": _MIXED,
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [1, 2, 3, 4]}},
    # 6. no vulnerable lines -> nothing applied -> safety 50 -> REJECTED (strict)
    {"input": {"file_path": "requirements.txt", "source_code": "flask\nrequests",
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": []}},
    # 7. empty source -> clean passthrough, not applied
    {"input": {"file_path": "empty.txt", "source_code": "",
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [1]}},
    # 8. unknown vulnerability_type -> all lines passed through unchanged
    {"input": {"file_path": "x.py", "source_code": "import os\nx = 1",
               "vulnerability_type": "SQL_INJECTION", "vulnerable_lines": [1, 2]}},
    # 9. non-strict env -> WARN_PATCH instead of REJECTED_PATCH (not applied)
    {"input": {"file_path": "requirements.txt", "source_code": "===garbage===",
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [1]},
     "env": {"PI_PATCH_STRICT_MODE": "false"}},
    # 10. strict env -> REJECTED_PATCH on a not-applied patch
    {"input": {"file_path": "requirements.txt", "source_code": "===garbage===",
               "vulnerability_type": "UNPINNED_DEP", "vulnerable_lines": [1]},
     "env": {"PI_PATCH_STRICT_MODE": "true"}},
]
