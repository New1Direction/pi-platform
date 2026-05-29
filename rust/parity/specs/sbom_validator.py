"""Parity spec for PiSBOMValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSBOMValidator"

_mod = load_py_agent("pi_sbom_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSBOMValidator()
    out = agent.validate_sbom(_mod.SBOMInput(**data))
    return out.model_dump()


# Clean SBOM: has a signature block, no banned/risky licenses -> PASSED.
_CLEAN = '{"bomFormat": "CycloneDX", "components": [], "signature": {"algorithm": "RS256"}}'
# Banned AGPL copyleft (risk 85) but signature present -> only license issue.
_AGPL = '{"components": [{"license": "AGPL-3.0"}], "attestation": "present"}'
# Risky GPL-3.0 (risk 50) but attestation present -> only license issue, WARN/FAILED.
_GPL3 = '{"components": [{"license": "GPL-3.0"}], "signature": "0xdeadbeef"}'
# GPLv3 spelling variant with attestation present.
_GPLV3 = 'PackageLicenseDeclared: GPLv3\nSignatureBlock: attestation here'
# No banned license but missing signature/attestation (risk 60).
_NOSIG = '{"components": [{"name": "left-pad", "version": "1.0.0"}]}'
# AGPL AND missing signature: both gates trip, risk maxes at 85.
_AGPL_NOSIG = '{"components": [{"license": "AGPL-3.0"}]}'
# Uppercase content to exercise .lower() normalization.
_UPPER = '{"COMPONENTS": [{"LICENSE": "GPL-3.0"}], "SIGNATURE": "ABC"}'

SAMPLES = [
    # Clean / passing input.
    {"input": {"sbom_path": "a.json", "sbom_content": _CLEAN, "format": "cyclonedx"}},
    # Banned AGPL copyleft license path.
    {"input": {"sbom_path": "a.json", "sbom_content": _AGPL, "format": "cyclonedx"}},
    # Risky GPL-3.0 license path.
    {"input": {"sbom_path": "a.json", "sbom_content": _GPL3, "format": "cyclonedx"}},
    # GPLv3 spelling variant.
    {"input": {"sbom_path": "a.spdx", "sbom_content": _GPLV3, "format": "spdx"}},
    # Missing signature/attestation path.
    {"input": {"sbom_path": "a.json", "sbom_content": _NOSIG, "format": "cyclonedx"}},
    # Both license + attestation gates trip.
    {"input": {"sbom_path": "a.json", "sbom_content": _AGPL_NOSIG, "format": "cyclonedx"}},
    # Uppercase content (case-insensitivity).
    {"input": {"sbom_path": "a.json", "sbom_content": _UPPER, "format": "cyclonedx"}},
    # Empty content edge case (no license, missing signature -> risk 60).
    {"input": {"sbom_path": "a.json", "sbom_content": "", "format": "cyclonedx"}},
    # Non-strict env -> risk>30 no longer fails; WARN path with is_secure True.
    {"input": {"sbom_path": "a.json", "sbom_content": _AGPL, "format": "cyclonedx"},
     "env": {"PI_SBOM_STRICT_MODE": "false"}},
    # Strict env explicit -> FAILED path.
    {"input": {"sbom_path": "a.json", "sbom_content": _AGPL, "format": "cyclonedx"},
     "env": {"PI_SBOM_STRICT_MODE": "true"}},
]
