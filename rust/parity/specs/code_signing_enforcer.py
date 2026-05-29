"""Parity spec for PiCodeSigningEnforcer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCodeSigningEnforcer"

_mod = load_py_agent("pi_code_signing_enforcer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCodeSigningEnforcer()
    out = agent.verify_signing(_mod.ArtifactInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean / passing artifact: no triggering substrings.
    {"input": {"artifact_metadata": "Build signed with valid certificate; checksum verified."}},
    # Unsigned build artifact (risk 90).
    {"input": {"artifact_metadata": "Container image is UNSIGNED and lacks provenance."}},
    # "signature: none" variant of the unsigned path.
    {"input": {"artifact_metadata": "manifest reports signature: none for the bundle"}},
    # Insecure signature anchor (risk 85) via "revoked".
    {"input": {"artifact_metadata": "Signing chain uses a REVOKED intermediate certificate."}},
    # Missing integrity checksum (risk 65).
    {"input": {"artifact_metadata": "pipeline config: checksum: false during packaging"}},
    # Checksum verification disabled phrasing.
    {"input": {"artifact_metadata": "Checksum Verification Disabled in release stage."}},
    # Multiple issues combined: unsigned + expired certificate + checksum disabled.
    {"input": {"artifact_metadata": "missing signature; expired certificate anchor; checksum: false"}},
    # Empty / edge input.
    {"input": {"artifact_metadata": ""}},
    # Non-strict env -> WARN_SIGNING path, is_secure stays True even at high risk.
    {"input": {"artifact_metadata": "Container image is UNSIGNED and lacks provenance."},
     "env": {"PI_ARTIFACT_STRICT_MODE": "false"}},
    # Strict env explicitly "true" -> FAILED path.
    {"input": {"artifact_metadata": "Container image is UNSIGNED and lacks provenance."},
     "env": {"PI_ARTIFACT_STRICT_MODE": "true"}},
]
