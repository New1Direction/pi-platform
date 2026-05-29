"""Parity spec for PiIaCScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiIaCScanner"

_mod = load_py_agent("pi_iac_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiIaCScanner()
    out = agent.scan_iac(_mod.IaCInput(**data))
    return out.model_dump()


# Clean template: no flagged substrings.
_CLEAN = "\n".join(
    [
        'resource "aws_s3_bucket" "b" {',
        '  acl = "private"',
        "  server_side_encryption_configuration {",
        '    sse_algorithm = "aws:kms"',
        "  }",
        "}",
    ]
)

# Public bucket via public-read ACL.
_PUBLIC_READ = 'resource "aws_s3_bucket_acl" "x" {\n  acl = "public-read"\n}'

# Public bucket via wildcard principal (CloudFormation JSON style).
_WILDCARD_PRINCIPAL = '{"Statement": [{"Effect": "Allow", "Principal": "*"}]}'

# Admin ingress: 0.0.0.0/0 together with port 22.
_ADMIN_INGRESS = "\n".join(
    [
        'resource "aws_security_group" "sg" {',
        "  ingress {",
        "    from_port   = 22",
        "    to_port     = 22",
        '    cidr_blocks = ["0.0.0.0/0"]',
        "  }",
        "}",
    ]
)

# Broad network: 0.0.0.0/0 present but NO "22"/"3389"/"cidr_blocks" substrings.
_BROAD_NETWORK = 'allowed_range = "0.0.0.0/0"'

# Disabled encryption.
_NO_ENCRYPTION = 'encryption = "disabled"'

# Combined: public-read + admin ingress + disabled encryption (max risk path).
_COMBINED = "\n".join([_PUBLIC_READ, _ADMIN_INGRESS, _NO_ENCRYPTION])

SAMPLES = [
    {"input": {"file_path": "main.tf", "iac_content": _CLEAN, "iac_type": "terraform"}},
    {"input": {"file_path": "acl.tf", "iac_content": _PUBLIC_READ, "iac_type": "terraform"}},
    {"input": {"file_path": "policy.json", "iac_content": _WILDCARD_PRINCIPAL, "iac_type": "cloudformation"}},
    {"input": {"file_path": "sg.tf", "iac_content": _ADMIN_INGRESS, "iac_type": "terraform"}},
    {"input": {"file_path": "net.tf", "iac_content": _BROAD_NETWORK, "iac_type": "terraform"}},
    {"input": {"file_path": "enc.tf", "iac_content": _NO_ENCRYPTION, "iac_type": "terraform"}},
    {"input": {"file_path": "all.tf", "iac_content": _COMBINED, "iac_type": "terraform"}},
    {"input": {"file_path": "empty.tf", "iac_content": "", "iac_type": "pulumi"}},
    # non-strict env -> high risk but is_secure stays True (WARN path)
    {"input": {"file_path": "acl.tf", "iac_content": _PUBLIC_READ, "iac_type": "terraform"},
     "env": {"PI_IAC_SCANNER_STRICT_MODE": "false"}},
    {"input": {"file_path": "acl.tf", "iac_content": _PUBLIC_READ, "iac_type": "terraform"},
     "env": {"PI_IAC_SCANNER_STRICT_MODE": "true"}},
]
