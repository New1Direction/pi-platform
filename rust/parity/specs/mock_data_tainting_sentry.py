"""Parity spec for PiMockDataTaintingSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiMockDataTaintingSentry"

_mod = load_py_agent("pi_mock_data_tainting_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiMockDataTaintingSentry()
    out = agent.check_mock_tainting(_mod.MockDataTaintingInput(**data))
    return out.model_dump()


# Clean fixture: localhost + obvious test data, nothing should flag.
_CLEAN = '{"host": "localhost", "user": "test_user", "token": "dummy"}'

# Distinct vulnerable paths -------------------------------------------------
# AWS access key (AKIA + 16). Contains "EXAMPLE" but starts with AKIA so the
# "example" skip does not apply.
_AWS = "aws_access_key_id = AWS_KEY_SCRUBBED"

# GitHub token (ghp_ + 36 chars).
_GITHUB = "gh_token = GITHUB_TOKEN_SCRUBBED"

# Production host reference.
_PROD_HOST = 'endpoint = "prod.payments.io"'

# Internal private IP (192.168.x.x branch).
_PRIVATE_IP = "db_host = 10.13.37.200"

# High-entropy API key / secret token (>=32 chars, high unique ratio).
_HIGH_ENTROPY = "secret = aZ9bX2cY7dW4eV5fU8gT3hS6iR1jQ0kP"

# A high-entropy-shaped string that is filtered out because it contains "test".
_TESTY_KEY = "key = test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Multi-line fixture mixing safe and tainted lines.
_MULTI = "\n".join(
    [
        '{"safe": "localhost", "note": "mock data only"}',
        "aws = AWS_KEY_SCRUBBED",
        "internal = 172.16.5.9",
        "comment = a perfectly normal sentence with short words",
        "prod = prod.api.com",
    ]
)

SAMPLES = [
    {"input": {"file_path": "fixtures/clean.json", "data_content": _CLEAN}},
    {"input": {"file_path": "fixtures/aws.json", "data_content": _AWS}},
    {"input": {"file_path": "fixtures/gh.json", "data_content": _GITHUB}},
    {"input": {"file_path": "fixtures/prod.json", "data_content": _PROD_HOST}},
    {"input": {"file_path": "fixtures/ip.json", "data_content": _PRIVATE_IP}},
    {"input": {"file_path": "fixtures/secret.env", "data_content": _HIGH_ENTROPY}},
    {"input": {"file_path": "fixtures/testy.env", "data_content": _TESTY_KEY}},
    {"input": {"file_path": "fixtures/multi.txt", "data_content": _MULTI}},
    {"input": {"file_path": "fixtures/empty.json", "data_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "fixtures/aws.json", "data_content": _AWS},
     "env": {"PI_MOCK_TAINT_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "fixtures/aws.json", "data_content": _AWS},
     "env": {"PI_MOCK_TAINT_STRICT_MODE": "true"}},
]
