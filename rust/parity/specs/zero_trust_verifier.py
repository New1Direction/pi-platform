"""Parity spec for PiZeroTrustVerifier.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZeroTrustVerifier"

_mod = load_py_agent("pi_zero_trust_verifier.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZeroTrustVerifier()
    out = agent.verify_zero_trust(_mod.ZeroTrustInput(**data))
    return out.model_dump()


_CLEAN = "ingress:\n  - from: trusted-namespace\nmtls: true\nrequire_mtls = true"
_WILDCARD = "ingress: []\negress:\n  - to: trusted"
_WILDCARD_STAR = "ingress:\n  - from: *\nmtls: true"
_INSECURE_PROTO = "endpoint: HTTP://service.internal/api"
_NO_MTLS = "ingress:\n  - from: trusted\nmtls: false"
# triggers every violation path at once (highest risk: 85.0)
_ALL = "ingress: []\nendpoint: telnet://legacy.box\nrequire_mtls = false"

SAMPLES = [
    {"input": {"network_policy_content": _CLEAN}},
    {"input": {"network_policy_content": _WILDCARD}},
    {"input": {"network_policy_content": _WILDCARD_STAR}},
    {"input": {"network_policy_content": _INSECURE_PROTO}},
    {"input": {"network_policy_content": _NO_MTLS}},
    {"input": {"network_policy_content": _ALL}},
    {"input": {"network_policy_content": ""}},
    # mTLS disabled (risk 70.0 > 30.0) but strict mode OFF -> WARN_ZERO_TRUST, is_secure True
    {"input": {"network_policy_content": _NO_MTLS},
     "env": {"PI_ZERO_TRUST_STRICT_MODE": "false"}},
    # same input, strict mode ON -> FAILED_ZERO_TRUST_COMPLIANCE
    {"input": {"network_policy_content": _NO_MTLS},
     "env": {"PI_ZERO_TRUST_STRICT_MODE": "true"}},
]
