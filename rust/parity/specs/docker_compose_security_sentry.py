"""Parity spec for PiDockerComposeSecuritySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDockerComposeSecuritySentry"

_mod = load_py_agent("pi_docker_compose_security_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDockerComposeSecuritySentry()
    out = agent.audit_docker_compose(_mod.DockerComposeSecurityInput(**data))
    return out.model_dump()


_CLEAN = "\n".join(
    [
        "services:",
        "  web:",
        "    image: nginx",
        "    ports:",
        '      - "80:80"',
        "    restart: always",
    ]
)

_PRIVILEGED = "\n".join(
    [
        "services:",
        "  bad:",
        "    image: nginx",
        "    privileged: true",
    ]
)

_DOCKER_SOCK = "\n".join(
    [
        "services:",
        "  ci:",
        "    image: docker",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock",
    ]
)

_ROOT_MOUNT = "\n".join(
    [
        "services:",
        "  backup:",
        "    image: alpine",
        "    volumes:",
        "      - /:/host",
    ]
)

_MULTI_VULN = "\n".join(
    [
        "version: '3'",
        "services:",
        "  app:",
        "    image: myapp",
        "    privileged: true",
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock",
        "      - /:/host",
        "  safe:",
        "    image: redis",
        "    ports:",
        '      - "6379:6379"',
    ]
)

# A bare `privileged: true` outside any detected service block: service_indent
# never gets set so current_service stays None and nothing is flagged.
_NO_SERVICE = "\n".join(
    [
        "# just a comment",
        "privileged: true",
    ]
)

SAMPLES = [
    {"input": {"file_path": "docker-compose.yml", "compose_code": _CLEAN}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _PRIVILEGED}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _DOCKER_SOCK}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _ROOT_MOUNT}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _MULTI_VULN}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _NO_SERVICE}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": ""}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _PRIVILEGED,
               "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "docker-compose.yml", "compose_code": _PRIVILEGED},
     "env": {"PI_DOCKER_COMPOSE_STRICT_MODE": "false"}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _PRIVILEGED},
     "env": {"PI_DOCKER_COMPOSE_STRICT_MODE": "true"}},
]
