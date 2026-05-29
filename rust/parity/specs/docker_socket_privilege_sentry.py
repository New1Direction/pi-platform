"""Parity spec for PiDockerSocketPrivilegeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDockerSocketPrivilegeSentry"

_mod = load_py_agent("pi_docker_socket_privilege_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDockerSocketPrivilegeSentry()
    out = agent.audit_docker_socket(_mod.DockerSocketPrivilegeInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "FROM alpine:3.19",
        "RUN apk add --no-cache curl",
        "CMD [\"sh\"]",
    ]
)
_COMPOSE_MOUNT = "\n".join(
    [
        "services:",
        "  agent:",
        "    image: ci-runner",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock",
    ]
)
_RUN_FLAG = "docker run -v /var/run/docker.sock:/var/run/docker.sock my-image"
_MULTI = "\n".join(
    [
        "version: '3'",
        "services:",
        "  a:",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock:ro",
        "  b:",
        "    volumes:",
        "      - ./data:/data",
        "  c:",
        "    volumes:",
        "      - /var/run/docker.sock",
    ]
)

SAMPLES = [
    # clean / passing config
    {"input": {"file_path": "Dockerfile", "dockerfile_code": _CLEAN}},
    # single docker.sock mount in a compose file -> REJECTED (strict default)
    {"input": {"file_path": "docker-compose.yml", "dockerfile_code": _COMPOSE_MOUNT}},
    # docker run -v flag on one line
    {"input": {"file_path": "run.sh", "dockerfile_code": _RUN_FLAG}},
    # multiple flagged lines mixed with safe lines
    {"input": {"file_path": "docker-compose.yml", "dockerfile_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "Dockerfile", "dockerfile_code": ""}},
    # non-default check_level still flags (logic ignores check_level field)
    {"input": {"file_path": "run.sh", "dockerfile_code": _RUN_FLAG, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "docker-compose.yml", "dockerfile_code": _COMPOSE_MOUNT},
     "env": {"PI_DOCKER_SOCKET_PRIVILEGE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED
    {"input": {"file_path": "docker-compose.yml", "dockerfile_code": _COMPOSE_MOUNT},
     "env": {"PI_DOCKER_SOCKET_PRIVILEGE_STRICT_MODE": "true"}},
]
