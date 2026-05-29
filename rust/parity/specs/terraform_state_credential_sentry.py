"""Parity spec for PiTerraformStateCredentialSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTerraformStateCredentialSentry"

_mod = load_py_agent("pi_terraform_state_credential_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTerraformStateCredentialSentry()
    out = agent.audit_terraform_credentials(_mod.TerraformStateCredentialInput(**data))
    return out.model_dump()


# A clean config that uses variable references -> not flagged.
_SECURE = "\n".join(
    [
        'provider "aws" {',
        "  region     = var.region",
        "  secret_key = var.aws_secret_key",
        "  access_key = local.access",
        "}",
    ]
)

# Hardcoded secret_key value -> flagged.
_HARDCODED_SECRET = 'secret_key = "AKIAIOSFODNN7EXAMPLEKEY"'

# Hardcoded password -> flagged.
_HARDCODED_PASSWORD = 'password = "superSecretPassword123"'

# token assigned a short value (<= 4 chars) -> NOT flagged.
_SHORT_TOKEN = 'token = "abcd"'

# Credential-looking assignment but inside a comment -> skipped.
_COMMENTED = '# secret_key = "AKIAIOSFODNN7EXAMPLEKEY"'

# // comment style also skipped.
_SLASH_COMMENTED = '// access_key = "AKIAIOSFODNN7EXAMPLEKEY"'

# Mixed file: one hardcoded finding, comments, var refs, short values.
_MULTI = "\n".join(
    [
        'provider "aws" {',
        "  region     = var.region",
        '  # access_key = "AKIAIOSFODNN7EXAMPLEKEY"',
        '  client_secret = "topSecretClientValue"',
        "  secret_key = var.aws_secret_key",
        '  token = "xy"',
    ]
)

# api_key with a mismatched quote pair (opens double, closes single) — mirrors
# the Python regex char class ["\'] on both ends (no backreference).
_MIXED_QUOTES = "api_key = \"longvalueheresecret'"

SAMPLES = [
    {"input": {"file_path": "main.tf", "tf_code": _SECURE}},
    {"input": {"file_path": "main.tf", "tf_code": _HARDCODED_SECRET}},
    {"input": {"file_path": "main.tf", "tf_code": _HARDCODED_PASSWORD}},
    {"input": {"file_path": "main.tf", "tf_code": _SHORT_TOKEN}},
    {"input": {"file_path": "main.tf", "tf_code": _COMMENTED}},
    {"input": {"file_path": "main.tf", "tf_code": _SLASH_COMMENTED}},
    {"input": {"file_path": "main.tf", "tf_code": _MULTI}},
    {"input": {"file_path": "main.tf", "tf_code": _MIXED_QUOTES}},
    {"input": {"file_path": "main.tf", "tf_code": ""}},
    # check_level is accepted but unused by the logic.
    {"input": {"file_path": "main.tf", "tf_code": _HARDCODED_SECRET, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "main.tf", "tf_code": _HARDCODED_SECRET},
     "env": {"PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "main.tf", "tf_code": _HARDCODED_SECRET},
     "env": {"PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE": "true"}},
]
