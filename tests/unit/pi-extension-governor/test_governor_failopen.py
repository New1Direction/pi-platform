"""Governor must reject high-risk extensions regardless of per-detector strict mode.

Finding: four of the five source scanners only rejected a >=71 risk when their
strict-mode toggle was on (`if risk >= 71.0 and is_*_strict_mode()`), so an
operator-controlled env var / config could silently downgrade a high-risk
admission to advisory — a per-detector kill switch. Only detect_prompt_injection
rejected unconditionally. The four must match it.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pi_extension_governor.governor import ExtensionGovernor
from pi_extension_governor.manifest import CapabilityClass, ExtensionBundle, ExtensionManifest, TrustZone
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_extension_governor.provenance import ExtensionProvenanceLedger
from pi_extension_governor.trust_zones import TrustZoneEnforcer


def _governor(td):
    return ExtensionGovernor(
        ExtensionGovernancePolicy(),
        ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger"),
        TrustZoneEnforcer(),
    )


def _bundle():
    manifest = ExtensionManifest(
        extension_id="x",
        package_name="x",
        package_version="1.0.0",
        package_hash="h",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )
    return ExtensionBundle(bundle_id="b", manifest=manifest, payload_hash="ph")


def test_high_shadow_risk_rejected_even_with_strict_mode_off(monkeypatch):
    # Force the shadow-parameter scanner to report high risk, and turn its
    # strict-mode toggle OFF. The bundle must still be rejected.
    monkeypatch.setattr(
        "pi_micro_agents.pi_schema_ghost.detect_shadow_parameters", lambda src: (95.0, ["shadow_param"])
    )
    monkeypatch.setattr("pi_micro_agents.pi_schema_ghost.is_strict_mode", lambda: False)

    with tempfile.TemporaryDirectory() as td:
        result = _governor(td).process_bundle(_bundle(), "OUTPUT = {}", {})
    assert result.admitted is False
    assert "shadow" in result.reason.lower()


def test_high_spend_risk_rejected_even_with_strict_mode_off(monkeypatch):
    monkeypatch.setattr("pi_micro_agents.pi_spend_hunter.detect_spend_anomalies", lambda src: (88.0, ["spend_anomaly"]))
    monkeypatch.setattr("pi_micro_agents.pi_spend_hunter.is_strict_mode", lambda: False)

    with tempfile.TemporaryDirectory() as td:
        result = _governor(td).process_bundle(_bundle(), "OUTPUT = {}", {})
    assert result.admitted is False
    assert "spend" in result.reason.lower()
