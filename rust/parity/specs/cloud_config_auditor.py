"""Parity spec for PiCloudConfigAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCloudConfigAuditor"

_mod = load_py_agent("pi_cloud_config_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCloudConfigAuditor()
    out = agent.audit_config(_mod.CloudConfigInput(**data))
    return out.model_dump()


# Unrestricted ingress: 0.0.0.0/0 with a triggering protocol/port marker.
_UNRESTRICTED = "\n".join(
    [
        "ingress:",
        "  - CidrIp: 0.0.0.0/0",
        "    IpProtocol: -1",
    ]
)
# IPv6 unrestricted ingress with port_range marker.
_UNRESTRICTED_V6 = "\n".join(
    [
        "ingress:",
        "  - CidrIpv6: ::/0",
        "    port_range: 0-65535",
    ]
)
# 0.0.0.0/0 present but NO triggering protocol/port marker -> not flagged.
_CIDR_NO_PROTO = "ingress:\n  - CidrIp: 0.0.0.0/0\n    Description: managed"

# AWS S3 public access block disabled.
_AWS_PUBLIC = "PublicAccessBlockConfiguration:\n  BlockPublicAcls: false"

# Logging disabled.
_LOGGING_OFF = "monitoring:\n  logging: disabled"

# GCP default network exposure.
_GCP_DEFAULT = "instance:\n  network: default\n  subnetwork: default"

# Clean / passing config.
_CLEAN = "instance:\n  network: hardened-vpc\n  logging: enabled\n  BlockPublicAcls: true"

# Combined: multiple findings, highest risk wins (max).
_COMBINED = "\n".join(
    [
        "ingress:",
        "  - CidrIp: 0.0.0.0/0",
        "    IpProtocol: tcp",
        "PublicAccessBlockConfiguration:",
        "  BlockPublicAcls: false",
        "monitoring:",
        "  logging: false",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "ok.yaml", "config_content": _CLEAN, "provider": "aws"}},
    # unrestricted firewall (IPv4, IpProtocol: -1)
    {"input": {"file_path": "sg.yaml", "config_content": _UNRESTRICTED, "provider": "aws"}},
    # unrestricted firewall (IPv6, port_range)
    {"input": {"file_path": "sg6.yaml", "config_content": _UNRESTRICTED_V6, "provider": "gcp"}},
    # CIDR open but no protocol/port marker -> not flagged
    {"input": {"file_path": "sg2.yaml", "config_content": _CIDR_NO_PROTO, "provider": "aws"}},
    # AWS public bucket
    {"input": {"file_path": "s3.yaml", "config_content": _AWS_PUBLIC, "provider": "aws"}},
    # AWS public-bucket marker present but provider is NOT aws -> not flagged for S3
    {"input": {"file_path": "s3.yaml", "config_content": _AWS_PUBLIC, "provider": "gcp"}},
    # logging disabled (risk 50 -> NON_COMPLIANT under strict default)
    {"input": {"file_path": "log.yaml", "config_content": _LOGGING_OFF, "provider": "azure"}},
    # GCP default network
    {"input": {"file_path": "gce.yaml", "config_content": _GCP_DEFAULT, "provider": "gcp"}},
    # empty / edge input
    {"input": {"file_path": "empty.yaml", "config_content": "", "provider": "aws"}},
    # combined findings -> max risk wins; non-strict env -> WARN, is_secure True
    {"input": {"file_path": "all.yaml", "config_content": _COMBINED, "provider": "AWS"},
     "env": {"PI_CLOUD_CONFIG_STRICT_MODE": "false"}},
    # same combined findings -> strict env -> NON_COMPLIANT
    {"input": {"file_path": "all.yaml", "config_content": _COMBINED, "provider": "AWS"},
     "env": {"PI_CLOUD_CONFIG_STRICT_MODE": "true"}},
]
