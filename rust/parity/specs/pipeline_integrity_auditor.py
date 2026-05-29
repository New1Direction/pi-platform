"""Parity spec for PiPipelineIntegrityAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiPipelineIntegrityAuditor"

_mod = load_py_agent("pi_pipeline_integrity_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiPipelineIntegrityAuditor()
    out = agent.audit_pipeline_integrity(_mod.PipelineIntegrityInput(**data))
    return out.model_dump()


# Clean / passing workflow: no github.event context, no write-all permissions.
_CLEAN = "\n".join(
    [
        "name: CI",
        "on: push",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - run: cargo test",
    ]
)

# Script injection: github.event.inputs + run: -> risk 90.
_INJECT_INPUTS = "\n".join(
    [
        "jobs:",
        "  greet:",
        "    steps:",
        "      - run: echo ${{ github.event.inputs.name }}",
    ]
)

# Script injection via github.head_ref + run: -> risk 90.
_INJECT_HEAD_REF = "\n".join(
    [
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: git checkout ${{ github.head_ref }}",
    ]
)

# github context present but NO "run:" step -> no flaw (clean).
_CONTEXT_NO_RUN = "\n".join(
    [
        "env:",
        "  REF: ${{ github.head_ref }}",
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
    ]
)

# Permissive access: permissions: write-all -> risk 65.
_WRITE_ALL = "\n".join(
    [
        "permissions: write-all",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
    ]
)

# Permissive access via empty permissions map -> risk 65.
_EMPTY_PERMS = "\n".join(
    [
        "permissions: {}",
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
    ]
)

# Both flaws: injection (90) + write-all (65) -> max risk 90, two flaws.
_BOTH = "\n".join(
    [
        "permissions: write-all",
        "jobs:",
        "  greet:",
        "    steps:",
        "      - run: echo ${{ github.event.inputs.cmd }}",
    ]
)

SAMPLES = [
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _CLEAN}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _INJECT_INPUTS}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _INJECT_HEAD_REF}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _CONTEXT_NO_RUN}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _WRITE_ALL}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _EMPTY_PERMS}},
    {"input": {"workflow_path": ".github/workflows/ci.yml", "workflow_content": _BOTH}},
    {"input": {"workflow_path": "empty.yml", "workflow_content": ""}},
]
