"""Parity spec for PiKubernetesRootExecutionLinter.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiKubernetesRootExecutionLinter"

_mod = load_py_agent("pi_kubernetes_root_execution_linter.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiKubernetesRootExecutionLinter()
    out = agent.audit_kubernetes_root(_mod.KubernetesRootExecutionInput(**data))
    return out.model_dump()


# Has securityContext AND runAsNonRoot: true, no runAsUser: 0 -> secure.
_SECURE = "\n".join(
    [
        "spec:",
        "  securityContext:",
        "    runAsNonRoot: true",
        "  containers:",
        "  - name: app",
    ]
)
# securityContext present but no runAsNonRoot: true -> flagged securityContext.
_CTX_NO_NONROOT = "\n".join(
    [
        "spec:",
        "  securityContext:",
        "    fsGroup: 2000",
    ]
)
# No securityContext at all -> missing securityContext.
_MISSING_CTX = "\n".join(
    [
        "spec:",
        "  containers:",
        "  - name: app",
        "    image: nginx",
    ]
)
# Explicit runAsUser: 0 (with space) -> per-line finding + still secure ctx.
_ROOT_USER_SPACE = "\n".join(
    [
        "spec:",
        "  securityContext:",
        "    runAsNonRoot: true",
        "    runAsUser: 0",
    ]
)
# Explicit runAsUser:0 (no space variant) plus missing securityContext.
_ROOT_USER_NOSPACE = "\n".join(
    [
        "spec:",
        "  containers:",
        "  - name: app",
        "    runAsUser:0",
    ]
)
# Multiple runAsUser: 0 lines exercising enumerate index correctness.
_MULTI_ROOT = "\n".join(
    [
        "spec:",
        "  securityContext:",
        "    runAsNonRoot: true",
        "    runAsUser: 0",
        "  initContainers:",
        "    runAsUser: 0",
    ]
)

SAMPLES = [
    {"input": {"file_path": "deploy.yaml", "yaml_code": _SECURE}},
    {"input": {"file_path": "deploy.yaml", "yaml_code": _CTX_NO_NONROOT}},
    {"input": {"file_path": "deploy.yaml", "yaml_code": _MISSING_CTX}},
    {"input": {"file_path": "deploy.yaml", "yaml_code": _ROOT_USER_SPACE}},
    {"input": {"file_path": "deploy.yaml", "yaml_code": _ROOT_USER_NOSPACE}},
    {"input": {"file_path": "deploy.yaml", "yaml_code": _MULTI_ROOT}},
    # empty input -> missing securityContext path.
    {"input": {"file_path": "deploy.yaml", "yaml_code": ""}},
    # check_level override (does not affect logic, exercises default field).
    {"input": {"file_path": "deploy.yaml", "yaml_code": _SECURE, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "deploy.yaml", "yaml_code": _MISSING_CTX},
     "env": {"PI_KUBERNETES_ROOT_EXECUTION_STRICT_MODE": "false"}},
    # strict env -> REJECTED path.
    {"input": {"file_path": "deploy.yaml", "yaml_code": _MISSING_CTX},
     "env": {"PI_KUBERNETES_ROOT_EXECUTION_STRICT_MODE": "true"}},
]
