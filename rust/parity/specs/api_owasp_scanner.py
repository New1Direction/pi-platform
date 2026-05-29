"""Parity spec for PiAPIOWASPScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiAPIOWASPScanner"

_mod = load_py_agent("pi_api_owasp_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAPIOWASPScanner()
    out = agent.scan_api(_mod.APIInput(**data))
    return out.model_dump()


# Clean schema: security present, limit/page/size present, no {id} path params.
_CLEAN = "\n".join(
    [
        "openapi: 3.0.0",
        "security:",
        "  - apiKey: []",
        "paths:",
        "  /items:",
        "    get:",
        "      parameters:",
        "        - name: limit",
        "          in: query",
    ]
)

# Missing security -> API2 (85.0). Has 'limit' so API4 not triggered. No {id}.
_NO_SECURITY = "\n".join(
    [
        "openapi: 3.0.0",
        "paths:",
        "  /items:",
        "    get:",
        "      parameters:",
        "        - name: limit",
        "          in: query",
    ]
)

# Security present, {id} path param without pattern -> API3 (60.0). Has 'size'.
_INSECURE_PATH = "\n".join(
    [
        "security:",
        "  - oauth2: []",
        "paths:",
        "  /users/{id}:",
        "    get:",
        "      parameters:",
        "        - name: size",
        "          in: query",
    ]
)

# Security present, {id} WITH pattern -> no API3. Has 'page'. Clean.
_PATH_WITH_PATTERN = "\n".join(
    [
        "security:",
        "  - oauth2: []",
        "paths:",
        "  /users/{id}:",
        "    get:",
        "      parameters:",
        "        - name: id",
        "          pattern: '^[0-9]+$'",
        "        - name: page",
        "          in: query",
    ]
)

# Security present, no {id}, but missing limit/page/size -> API4 (70.0).
_NO_PAGINATION = "\n".join(
    [
        "security:",
        "  - apiKey: []",
        "paths:",
        "  /items:",
        "    get:",
        "      responses:",
        "        '200':",
        "          description: ok",
    ]
)

# Everything bad: no security (85), {id} no pattern (60), no pagination (70) -> 85.0.
_ALL_BAD = "\n".join(
    [
        "openapi: 3.0.0",
        "paths:",
        "  /users/{id}:",
        "    get:",
        "      responses:",
        "        '200':",
        "          description: ok",
    ]
)

# JSON-style schema using "security" and "pattern" double-quoted keys.
_JSON_STYLE = (
    '{"openapi":"3.0.0","security":[{"apiKey":[]}],'
    '"paths":{"/users/{id}":{"get":{"parameters":'
    '[{"name":"id","pattern":"^[0-9]+$"},{"name":"limit"}]}}}}'
)

SAMPLES = [
    {"input": {"api_path": "openapi.yaml", "schema_content": _CLEAN}},
    {"input": {"api_path": "openapi.yaml", "schema_content": _NO_SECURITY}},
    {"input": {"api_path": "openapi.yaml", "schema_content": _INSECURE_PATH}},
    {"input": {"api_path": "openapi.yaml", "schema_content": _PATH_WITH_PATTERN}},
    {"input": {"api_path": "openapi.yaml", "schema_content": _NO_PAGINATION}},
    {"input": {"api_path": "openapi.yaml", "schema_content": _ALL_BAD}},
    {"input": {"api_path": "openapi.json", "schema_content": _JSON_STYLE}},
    # Empty schema: no security, no {id}, no limit/page/size -> API2 + API4 -> 85.0.
    {"input": {"api_path": "empty.yaml", "schema_content": ""}},
    # Non-strict env: risk present but is_secure coerced True -> WARN_API_COMPLIANCE.
    {"input": {"api_path": "openapi.yaml", "schema_content": _NO_SECURITY},
     "env": {"PI_API_STRICT_MODE": "false"}},
    # Strict env explicitly true: risk -> FAILED.
    {"input": {"api_path": "openapi.yaml", "schema_content": _NO_SECURITY},
     "env": {"PI_API_STRICT_MODE": "true"}},
]
