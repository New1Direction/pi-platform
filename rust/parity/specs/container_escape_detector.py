"""Parity spec for PiContainerEscapeDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiContainerEscapeDetector"

_mod = load_py_agent("pi_container_escape_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiContainerEscapeDetector()
    out = agent.scan_container_escape(_mod.ContainerEscapeInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "apiVersion: v1",
        "kind: Pod",
        "spec:",
        "  containers:",
        "  - name: app",
        "    image: nginx:latest",
    ]
)

_PRIVILEGED = "\n".join(
    [
        "spec:",
        "  containers:",
        "  - name: app",
        "    securityContext:",
        "      privileged: true",
    ]
)

_HOST_NS = "\n".join(
    [
        "spec:",
        "  hostNetwork: true",
        "  hostPID: true",
    ]
)

_HOSTPATH = "\n".join(
    [
        "spec:",
        "  volumes:",
        "  - name: host-root",
        "    hostPath:",
        "      path: /",
    ]
)

_CAPS = "\n".join(
    [
        "securityContext:",
        "  capabilities:",
        "    add:",
        "    - SYS_ADMIN",
        "    - NET_ADMIN",
    ]
)

_ALL_CAPS = "\n".join(
    [
        "securityContext:",
        "  capabilities:",
        "    add: [ALL]",
    ]
)

_FULL = "\n".join(
    [
        "spec:",
        "  hostIPC: true",
        "  containers:",
        "  - name: app",
        "    securityContext:",
        "      privileged: true",
        "    volumes:",
        "    - hostPath:",
        "        path: /etc",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "clean.yaml", "config_content": _CLEAN}},
    # privileged only (score 40 -> FAILED, exactly at boundary)
    {"input": {"file_path": "priv.yaml", "config_content": _PRIVILEGED}},
    # host namespace sharing
    {"input": {"file_path": "hostns.yaml", "config_content": _HOST_NS}},
    # writeable hostPath mount
    {"input": {"file_path": "hostpath.yaml", "config_content": _HOSTPATH}},
    # dangerous capabilities SYS_ADMIN / NET_ADMIN
    {"input": {"file_path": "caps.yaml", "config_content": _CAPS}},
    # "all" bare substring path
    {"input": {"file_path": "allcaps.yaml", "config_content": _ALL_CAPS}},
    # multiple vectors -> capped at 100
    {"input": {"file_path": "full.yaml", "config_content": _FULL}},
    # empty / edge input (note: "" contains no triggers)
    {"input": {"file_path": "empty.yaml", "config_content": ""}},
]
