"""Parity spec for PiDockerComposePortExposureSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDockerComposePortExposureSentry"

_mod = load_py_agent("pi_docker_compose_port_exposure_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDockerComposePortExposureSentry()
    out = agent.audit_docker_compose_ports(
        _mod.DockerComposePortExposureInput(**data)
    )
    return out.model_dump()


# Clean: sensitive port but bound to loopback only -> not exposed.
_CLEAN = "\n".join(
    [
        "services:",
        "  web:",
        "    image: nginx",
        "    ports:",
        "      - 127.0.0.1:8080:8080",
    ]
)

# Wildcard 0.0.0.0 binding of a database port.
_WILDCARD_DB = "\n".join(
    [
        "services:",
        "  db:",
        "    image: postgres",
        "    ports:",
        "      - 0.0.0.0:5432:5432",
    ]
)

# Default binding (no ip, no localhost) of a sensitive port -> still flagged
# because `exposed_wildcard` is True when neither 127.0.0.1 nor localhost present.
_DEFAULT_BIND = "\n".join(
    [
        "services:",
        "  cache:",
        "    image: redis",
        "    ports:",
        "      - 6379:6379",
    ]
)

# Multiple services, mix of secure and vulnerable, plus comments and blank lines.
_MULTI = "\n".join(
    [
        "# top level comment",
        "services:",
        "",
        "  api:",
        "    image: myapi",
        "    ports:",
        "      - 127.0.0.1:9000:9000",
        "  mongo:",
        "    image: mongo",
        "    ports:",
        "      - 0.0.0.0:27017:27017",
        "      - 23:23",
        "  ui:",
        "    image: ui",
        "    ports:",
        "      - 3000:3000",
    ]
)

# Sensitive-looking number embedded as substring (e.g. 18080 contains 8080,
# 192.168 etc.) to exercise naive substring matching semantics.
_SUBSTRING = "\n".join(
    [
        "services:",
        "  admin:",
        "    image: admin",
        "    ports:",
        "      - 18080:80",
    ]
)

# Non-sensitive port, public binding -> not flagged (no sensitive port match).
_PUBLIC_SAFE = "\n".join(
    [
        "services:",
        "  proxy:",
        "    image: caddy",
        "    ports:",
        "      - 0.0.0.0:443:443",
    ]
)

# No `services:` block at all -> nothing scanned.
_NO_SERVICES = "\n".join(
    [
        "version: '3'",
        "volumes:",
        "  data:",
    ]
)

SAMPLES = [
    {"input": {"file_path": "docker-compose.yml", "compose_code": _CLEAN}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _WILDCARD_DB}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _DEFAULT_BIND}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _MULTI}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _SUBSTRING}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _PUBLIC_SAFE}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _NO_SERVICES}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": ""}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _WILDCARD_DB,
               "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "docker-compose.yml", "compose_code": _WILDCARD_DB},
     "env": {"PI_DOCKER_COMPOSE_PORT_STRICT_MODE": "false"}},
    {"input": {"file_path": "docker-compose.yml", "compose_code": _WILDCARD_DB},
     "env": {"PI_DOCKER_COMPOSE_PORT_STRICT_MODE": "true"}},
]
