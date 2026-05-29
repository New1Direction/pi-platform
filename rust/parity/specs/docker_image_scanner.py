"""Parity spec for PiDockerImageScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDockerImageScanner"

_mod = load_py_agent("pi_docker_image_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDockerImageScanner()
    out = agent.scan_docker_image(_mod.DockerImageInput(**data))
    return out.model_dump()


# Clean: pinned base image (has ':' tag, no "latest") + explicit non-root USER.
_CLEAN = "\n".join(
    [
        "FROM python:3.11-slim",
        "USER appuser",
        "CMD [\"python\", \"app.py\"]",
    ]
)

# Secret in ENV (+30) only.
_ENV_SECRET = "\n".join(
    [
        "FROM python:3.11-slim",
        "USER appuser",
        "ENV API_KEY=supersecret",
    ]
)

# Explicit root user (+25) plus latest tag (+20).
_ROOT_AND_LATEST = "\n".join(
    [
        "FROM ubuntu:latest",
        "USER root",
    ]
)

# Unpinned base image (no ':' => +20) and no USER (+15) => 35.0, still secure.
_UNPINNED_NO_USER = "\n".join(
    [
        "FROM alpine",
        "RUN apk add --no-cache curl",
    ]
)

# Everything wrong: latest tag (+20), root user (+25), secret env (+30),
# no non-root USER so missing-user warning also fires (+15) => 90.0.
_ALL_BAD = "\n".join(
    [
        "FROM debian:latest",
        "ENV DB_PASSWORD=hunter2",
        "USER 0",
        "ENV AUTH_TOKEN=abc",
    ]
)

# USER 0 is treated as root; "0" == user_val branch.
_USER_ZERO = "\n".join(
    [
        "FROM python:3.11-slim",
        "USER 0",
    ]
)

# Indented lines (exercise .strip()) + a FROM with digest-style ':' that pins.
_INDENTED = "\n".join(
    [
        "   FROM golang:1.22-alpine   ",
        "\tUSER builder",
        "   ENV SOME_VALUE=plainish",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _CLEAN}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _ENV_SECRET}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _ROOT_AND_LATEST}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _UNPINNED_NO_USER}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _ALL_BAD}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _USER_ZERO}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _INDENTED}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": ""}},
    # Env var is defined in the module but NEVER used by scan_docker_image; these
    # two samples confirm both branches produce identical output regardless.
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _ROOT_AND_LATEST},
     "env": {"PI_DOCKER_IMAGE_STRICT_MODE": "false"}},
    {"input": {"file_path": "Dockerfile", "dockerfile_content": _ROOT_AND_LATEST},
     "env": {"PI_DOCKER_IMAGE_STRICT_MODE": "true"}},
]
