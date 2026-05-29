"""Parity spec for PiKubernetesSecurityAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiKubernetesSecurityAuditor"

_mod = load_py_agent("pi_kubernetes_security_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiKubernetesSecurityAuditor()
    out = agent.audit_k8s(_mod.K8sInput(**data))
    return out.model_dump()


# Clean: has resources, no privileged/default-ns/hostPath -> PASSED, risk 0.0
_CLEAN = "\n".join(
    [
        "spec:",
        "  containers:",
        "  - name: app",
        "    image: nginx@sha256:abc",
        "    resources:",
        "      limits:",
        "        cpu: 100m",
        "        memory: 128Mi",
    ]
)

# Privileged container (YAML form) -> 95.0
_PRIVILEGED = "\n".join(
    [
        "securityContext:",
        "  privileged: true",
        "resources:",
        "  limits: {}",
    ]
)

# Default namespace (YAML form) -> 40.0, resources present
_DEFAULT_NS = "\n".join(
    [
        "metadata:",
        "  namespace: default",
        "spec:",
        "  resources: {}",
    ]
)

# Missing resource constraints -> 60.0 (no "resources:" / '"resources"')
_MISSING_RES = "\n".join(
    [
        "spec:",
        "  containers:",
        "  - name: app",
        "    image: nginx",
    ]
)

# HostPath mount (YAML form) -> 80.0, resources present to isolate the hostPath path
_HOSTPATH = "\n".join(
    [
        "spec:",
        "  resources: {}",
        "  volumes:",
        "  - name: data",
        "    hostPath:",
        "      path: /var/lib",
    ]
)

# JSON-form manifest exercising the quoted-key branches; multiple violations.
_JSON_MULTI = (
    '{"metadata": {"namespace": "default"}, '
    '"spec": {"securityContext": {"privileged": true}, '
    '"volumes": [{"hostPath": {"path": "/data"}}]}}'
)

SAMPLES = [
    # Clean passing input.
    {"input": {"k8s_content": _CLEAN}},
    # Privileged execution (YAML).
    {"input": {"k8s_content": _PRIVILEGED}},
    # Default namespace (YAML).
    {"input": {"k8s_content": _DEFAULT_NS}},
    # Missing resource constraints.
    {"input": {"k8s_content": _MISSING_RES}},
    # HostPath injection (YAML).
    {"input": {"k8s_content": _HOSTPATH}},
    # JSON-form manifest hitting quoted-key branches + multiple violations
    # (privileged 95, default-ns 40, missing resources 60, hostPath 80).
    {"input": {"k8s_content": _JSON_MULTI}},
    # Empty input -> only the missing-resources violation fires (risk 60.0).
    {"input": {"k8s_content": ""}},
    # Non-strict env -> risk > 30 stays WARN_COMPLIANCE, is_secure True.
    {"input": {"k8s_content": _DEFAULT_NS},
     "env": {"PI_K8S_STRICT_MODE": "false"}},
    # Strict env explicitly true -> FAILED_COMPLIANCE.
    {"input": {"k8s_content": _DEFAULT_NS},
     "env": {"PI_K8S_STRICT_MODE": "true"}},
]
