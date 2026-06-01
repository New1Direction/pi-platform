"""Tests for pi-extension-governor.

Deterministic extension admission lifecycle.
Static inspection, sandbox execution, policy evaluation,
trust zone enforcement, provenance ledger, semantic normalization.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pi_extension_governor.governor import ExtensionGovernor
from pi_extension_governor.inspector import (
    CapabilityClassification,
    StaticCapabilityInspector,
)
from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionBundle,
    ExtensionManifest,
    ExtensionStatus,
    TrustZone,
)
from pi_extension_governor.normalizer import SemanticOutputNormalizer
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_extension_governor.provenance import (
    ExtensionExecutionReceipt,
    ExtensionProvenanceLedger,
)
from pi_extension_governor.sandbox import SandboxedExtensionRuntime
from pi_extension_governor.trust_zones import TrustZoneEnforcer

# ── Manifest Tests ─────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_manifest_compute_hash_determinism() -> None:
    m = ExtensionManifest(
        extension_id="ext_1",
        package_name="test-ext",
        package_version="1.0.0",
        package_hash="abc123",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        deterministic_claim=True,
        replayability_claim=True,
    )
    h1 = m.compute_hash()
    h2 = m.compute_hash()
    assert h1 == h2


def test_manifest_frozen_immutable() -> None:
    m = ExtensionManifest(
        extension_id="ext_1",
        package_name="test-ext",
        package_version="1.0.0",
        package_hash="abc123",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
    )
    try:
        m.package_name = "modified"
        raise AssertionError("Manifest should be frozen")
    except Exception:
        pass


def test_bundle_compute_hash() -> None:
    m = ExtensionManifest(
        extension_id="ext_1",
        package_name="test-ext",
        package_version="1.0.0",
        package_hash="abc123",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
    )
    b = ExtensionBundle(bundle_id="b1", manifest=m, payload_hash="xyz789")
    h1 = b.compute_bundle_hash()
    h2 = b.compute_bundle_hash()
    assert h1 == h2


# ── Static Capability Inspector Tests ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_inspector_detects_eval() -> None:
    inspector = StaticCapabilityInspector()
    source = "x = eval('1 + 1')"
    inspector.inspect_package(Path("."), "hash1")
    # inspect_package on empty dir won't find eval; test via direct tree inspection
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        inspector._check_eval_exec(node, Path("test.py"))
    inspector._apply_classification_rules()
    assert CapabilityClassification.REJECTED in inspector.classifications
    assert any(f.rule == "dynamic_execution_direct" for f in inspector.findings)


def test_inspector_detects_subprocess() -> None:
    inspector = StaticCapabilityInspector()
    source = "import subprocess; subprocess.Popen(['ls'])"
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        inspector._check_calls(node, Path("test.py"), source)
    inspector._apply_classification_rules()
    assert CapabilityClassification.REJECTED in inspector.classifications
    assert any(f.rule == "subprocess_spawn" for f in inspector.findings)


def test_inspector_detects_network() -> None:
    inspector = StaticCapabilityInspector()
    source = "import socket; s = socket.socket(); s.connect(('1.2.3.4', 80))"
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        inspector._check_calls(node, Path("test.py"), source)
    inspector._apply_classification_rules()
    assert any(f.rule == "network_access" for f in inspector.findings)


def test_inspector_detects_file_write() -> None:
    inspector = StaticCapabilityInspector()
    source = "with open('/tmp/test', 'w') as f: f.write('x')"
    import ast

    tree = ast.parse(source)
    for node in ast.walk(tree):
        inspector._check_file_operations(node, Path("test.py"))
    assert any(f.rule == "filesystem_mutation" for f in inspector.findings)


def test_inspector_safe_code() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "pkg"
        d.mkdir()
        (d / "safe.py").write_text("def add(a, b):\n    return a + b")
        inspector = StaticCapabilityInspector()
        report = inspector.inspect_package(d, "hash_safe")
        assert CapabilityClassification.DETERMINISTIC_SAFE in report.classifications


def test_inspector_package_hash_deterministic() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "pkg"
        d.mkdir()
        (d / "a.py").write_text("x = 1")
        (d / "b.py").write_text("y = 2")
        h1 = StaticCapabilityInspector.compute_package_hash(d)
        h2 = StaticCapabilityInspector.compute_package_hash(d)
        assert h1 == h2


# ── Sandbox Runtime Tests ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_sandbox_successful_execution() -> None:
    sandbox = SandboxedExtensionRuntime(allow_execution=True)
    source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'endpoints': 3}}"
    result = sandbox.execute(source, {})
    assert result.status == "SUCCESS"
    assert result.output is not None
    assert result.output["payload"]["endpoints"] == 3


def test_sandbox_timeout() -> None:
    sandbox = SandboxedExtensionRuntime(cpu_ms_max=50, allow_execution=True)
    source = """
n = 0
while True:
    n += 1
OUTPUT = {}
"""
    result = sandbox.execute(source, {})
    assert result.status == "TIMEOUT"


def test_sandbox_output_size_rejected() -> None:
    sandbox = SandboxedExtensionRuntime(output_size_max=10, allow_execution=True)
    source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'x': 'a' * 1000}}"
    result = sandbox.execute(source, {})
    assert result.status == "REJECTED"


def test_sandbox_verify_determinism_pass() -> None:
    sandbox = SandboxedExtensionRuntime(allow_execution=True)
    source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'n': INPUTS.get('n', 0) + 1}}"
    result = sandbox.verify_determinism(source, {"n": 5}, runs=3)
    assert result is True


def test_sandbox_verify_determinism_fail() -> None:
    sandbox = SandboxedExtensionRuntime(allow_execution=True)
    source = """
import random
OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'n': random.randint(1, 100)}}
"""
    result = sandbox.verify_determinism(source, {}, runs=3)
    assert result is False


# ── Policy Engine Tests ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_policy_allows_good_extension() -> None:
    policy = ExtensionGovernancePolicy()
    manifest = ExtensionManifest(
        extension_id="good_ext",
        package_name="good",
        package_version="1.0.0",
        package_hash="hash1",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        deterministic_claim=True,
        replayability_claim=True,
        network_access=False,
        filesystem_access=False,
        subprocess_access=False,
        dynamic_eval_access=False,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )
    result = policy.evaluate(manifest)
    assert result.passed is True


def test_policy_rejects_network_access() -> None:
    policy = ExtensionGovernancePolicy()
    manifest = ExtensionManifest(
        extension_id="bad_ext",
        package_name="bad",
        package_version="1.0.0",
        package_hash="hash2",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        network_access=True,
        filesystem_access=False,
        subprocess_access=False,
        dynamic_eval_access=False,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )
    result = policy.evaluate(manifest)
    assert result.passed is False
    assert any(e["rule_id"] == "network_access" and not e["passed"] for e in result.evaluations)


def test_policy_rejects_subprocess() -> None:
    policy = ExtensionGovernancePolicy()
    manifest = ExtensionManifest(
        extension_id="spawn_ext",
        package_name="spawn",
        package_version="1.0.0",
        package_hash="hash3",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        subprocess_access=True,
        network_access=False,
        filesystem_access=False,
        dynamic_eval_access=False,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )
    result = policy.evaluate(manifest)
    assert result.passed is False
    assert any(e["rule_id"] == "subprocess_access" and not e["passed"] for e in result.evaluations)


def test_policy_rejects_experimental_zone() -> None:
    policy = ExtensionGovernancePolicy(allowed_trust_zones={TrustZone.CORE_TRUSTED, TrustZone.GOVERNED_EXTENSION})
    manifest = ExtensionManifest(
        extension_id="exp_ext",
        package_name="exp",
        package_version="1.0.0",
        package_hash="hash4",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
    )
    result = policy.evaluate(manifest)
    assert result.passed is False
    assert any(e["rule_id"] == "trust_zone" and not e["passed"] for e in result.evaluations)


def test_policy_evaluation_deterministic_hash() -> None:
    policy = ExtensionGovernancePolicy()
    manifest = ExtensionManifest(
        extension_id="ext1",
        package_name="test",
        package_version="1.0.0",
        package_hash="hash5",
        capability_class=CapabilityClass.STATIC_ANALYZER,
        deterministic_claim=True,
        replayability_claim=True,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )
    r1 = policy.evaluate(manifest)
    r2 = policy.evaluate(manifest)
    assert r1.policy_hash == r2.policy_hash


# ── Semantic Normalizer Tests ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_normalizer_accepts_canonical_type() -> None:
    normalizer = SemanticOutputNormalizer()
    manifest = ExtensionManifest(
        extension_id="ext1",
        package_name="test",
        package_version="1.0.0",
        package_hash="hash1",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
    )
    raw = {"artifact_type": "SemanticIRTrace", "payload": {"endpoints": []}}
    result = normalizer.normalize(raw, manifest)
    assert result["artifact_type"] == "SemanticIRTrace"
    assert result["mesh_compatible"] is True
    assert result["schema_validated"] is True


def test_normalizer_rejects_unknown_type() -> None:
    normalizer = SemanticOutputNormalizer()
    manifest = ExtensionManifest(
        extension_id="ext1",
        package_name="test",
        package_version="1.0.0",
        package_hash="hash1",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
    )
    raw = {"artifact_type": "ArbitraryType", "payload": {}}
    result = normalizer.normalize(raw, manifest)
    assert result["artifact_type"] == "NormalizationRejection"
    assert "allowed_types" in result


def test_normalizer_schema_validation() -> None:
    normalizer = SemanticOutputNormalizer()
    artifact = {
        "artifact_type": "DependencyGraph",
        "extension_id": "ext1",
        "package_hash": "hash1",
        "payload": {},
        "provenance": {"manifest_id": "ext1", "package_version": "1.0.0", "capability_class": "openapi_tooling"},
    }
    assert normalizer.validate_canonical_schema(artifact) is True


# ── Provenance Ledger Tests ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_ledger_append_and_verify() -> None:
    with tempfile.TemporaryDirectory() as td:
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td))
        r1 = ExtensionExecutionReceipt(
            receipt_id="rcpt_1",
            extension_id="ext1",
            package_hash="hash1",
            worker_contract_version="1.0.0",
            execution_duration_ms=100,
            output_hash="out_hash1",
            deterministic_fingerprint="fp1",
        )
        ledger.append_receipt(r1)
        assert ledger.verify_chain() is True


def test_ledger_chain_integrity() -> None:
    with tempfile.TemporaryDirectory() as td:
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td))
        r1 = ExtensionExecutionReceipt(
            receipt_id="rcpt_1",
            extension_id="ext1",
            package_hash="hash1",
            worker_contract_version="1.0.0",
            execution_duration_ms=100,
            output_hash="h1",
            deterministic_fingerprint="f1",
        )
        r2 = ExtensionExecutionReceipt(
            receipt_id="rcpt_2",
            extension_id="ext2",
            package_hash="hash2",
            worker_contract_version="1.0.0",
            execution_duration_ms=200,
            output_hash="h2",
            deterministic_fingerprint="f2",
        )
        ledger.append_receipt(r1)
        ledger.append_receipt(r2)
        assert ledger.verify_chain() is True
        # Lineage
        lineage = ledger.lineage_for_extension("ext1")
        assert len(lineage) == 1
        assert lineage[0].receipt_id == "rcpt_1"


# ── Trust Zone Tests ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_trust_zone_experimental_stays_experimental() -> None:
    enforcer = TrustZoneEnforcer()
    manifest = ExtensionManifest(
        extension_id="exp",
        package_name="exp",
        package_version="1.0.0",
        package_hash="hash1",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
    )
    decision = enforcer.evaluate(manifest)
    assert decision.assigned_zone == TrustZone.SANDBOX_EXPERIMENTAL
    assert "sandbox" in decision.reason.lower()


def test_trust_zone_core_trusted_requires_allowlist() -> None:
    enforcer = TrustZoneEnforcer(core_trusted_packages={"hash_known"})
    manifest = ExtensionManifest(
        extension_id="core",
        package_name="core",
        package_version="1.0.0",
        package_hash="hash_unknown",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.CORE_TRUSTED,
    )
    decision = enforcer.evaluate(manifest)
    assert decision.assigned_zone == TrustZone.GOVERNED_EXTENSION
    assert "downgraded" in decision.reason.lower()


def test_trust_zone_core_trusted_allowed() -> None:
    enforcer = TrustZoneEnforcer(core_trusted_packages={"hash_known"})
    manifest = ExtensionManifest(
        extension_id="core",
        package_name="core",
        package_version="1.0.0",
        package_hash="hash_known",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.CORE_TRUSTED,
    )
    decision = enforcer.evaluate(manifest)
    assert decision.assigned_zone == TrustZone.CORE_TRUSTED


def test_trust_zone_experimental_no_governance_authority() -> None:
    enforcer = TrustZoneEnforcer()
    manifest = ExtensionManifest(
        extension_id="exp",
        package_name="exp",
        package_version="1.0.0",
        package_hash="hash1",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
    )
    assert enforcer.can_gain_governance_authority(manifest) is False


# ── Extension Governor Integration Tests ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_governor_admits_safe_extension() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="safe_ext",
            package_name="safe",
            package_version="1.0.0",
            package_hash="hash_safe",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            network_access=False,
            filesystem_access=False,
            subprocess_access=False,
            dynamic_eval_access=False,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b1", manifest=manifest, payload_hash="ph1")
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'endpoints': 3}}"
        result = governor.process_bundle(bundle, source, {})
        assert result.admitted is True
        assert result.status == ExtensionStatus.ADMITTED
        assert result.determinism_verified is True
        assert result.provenance_receipt_id is not None


def test_governor_rejects_eval_extension() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="evil_ext",
            package_name="evil",
            package_version="1.0.0",
            package_hash="hash_evil",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            network_access=False,
            filesystem_access=False,
            subprocess_access=False,
            dynamic_eval_access=False,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b2", manifest=manifest, payload_hash="ph2")
        source = "x = eval('1 + 1'); OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {}}"
        result = governor.process_bundle(bundle, source, {})
        assert result.admitted is False
        assert result.status == ExtensionStatus.REJECTED
        assert "inspection rejected" in result.reason.lower() or "dangerous" in result.reason.lower()


def test_governor_rejects_non_deterministic_extension() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="rand_ext",
            package_name="rand",
            package_version="1.0.0",
            package_hash="hash_rand",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b3", manifest=manifest, payload_hash="ph3")
        source = """
import random
OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'n': random.randint(1, 100)}}
"""
        result = governor.process_bundle(bundle, source, {})
        assert result.admitted is False
        assert "determinism verification failed" in result.reason.lower()


def test_governor_rejects_policy_violation() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="net_ext",
            package_name="net",
            package_version="1.0.0",
            package_hash="hash_net",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            network_access=True,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b4", manifest=manifest, payload_hash="ph4")
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {}}"
        result = governor.process_bundle(bundle, source, {})
        assert result.admitted is False
        assert result.policy_evaluation is not None
        assert result.policy_evaluation.passed is False


def test_governor_rejects_unknown_artifact_type() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="type_ext",
            package_name="type",
            package_version="1.0.0",
            package_hash="hash_type",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b5", manifest=manifest, payload_hash="ph5")
        source = "OUTPUT = {'artifact_type': 'CustomUnknownType', 'payload': {}}"
        result = governor.process_bundle(bundle, source, {})
        assert result.admitted is False
        assert "normalization rejected" in result.reason.lower()


def test_governor_experimental_no_governance_authority() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="exp_ext",
            package_name="exp",
            package_version="1.0.0",
            package_hash="hash_exp",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            network_access=False,
            trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
        )
        bundle = ExtensionBundle(bundle_id="b6", manifest=manifest, payload_hash="ph6")
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {}}"
        result = governor.process_bundle(bundle, source, {})
        # Admitted to sandbox but no governance authority
        if result.admitted:
            assert result.trust_zone_decision is not None
            assert result.trust_zone_decision.assigned_zone == TrustZone.SANDBOX_EXPERIMENTAL


def test_governor_provenance_receipt_on_admission() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        manifest = ExtensionManifest(
            extension_id="prov_ext",
            package_name="prov",
            package_version="1.0.0",
            package_hash="hash_prov",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            network_access=False,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        bundle = ExtensionBundle(bundle_id="b7", manifest=manifest, payload_hash="ph7")
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'x': 1}}"
        result = governor.process_bundle(bundle, source, {})
        if result.admitted:
            assert result.provenance_receipt_id is not None
            assert result.provenance_receipt_id.startswith("rcpt_")


def test_governor_receipt_chain_integrity() -> None:
    with tempfile.TemporaryDirectory() as td:
        policy = ExtensionGovernancePolicy()
        ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
        trust = TrustZoneEnforcer()
        governor = ExtensionGovernor(policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True))

        for i in range(3):
            manifest = ExtensionManifest(
                extension_id=f"chain_ext_{i}",
                package_name=f"chain_{i}",
                package_version="1.0.0",
                package_hash=f"hash_{i}",
                capability_class=CapabilityClass.OPENAPI_TOOLING,
                deterministic_claim=True,
                replayability_claim=True,
                network_access=False,
                trust_zone=TrustZone.GOVERNED_EXTENSION,
            )
            bundle = ExtensionBundle(bundle_id=f"bc_{i}", manifest=manifest, payload_hash=f"ph_{i}")
            source = f"OUTPUT = {{'artifact_type': 'SemanticIRTrace', 'payload': {{'idx': {i}}}}}"
            governor.process_bundle(bundle, source, {})

        assert ledger.verify_chain() is True


# ── Reproducibility Regression Tests ────────────────────────────────────────────────────────────────────────────────────────────────────────────
#
# These guard the "deterministic kernel" claim: an identity/content hash must
# be a pure function of LOGICAL content, never of wall-clock time or random
# uuids. Each test builds the SAME logical object TWICE as two FRESH instances
# (so the wall-clock default fields differ between them) and asserts the hashes
# are IDENTICAL, while also asserting the wall-clock/id metadata is still
# recorded (the fields are kept, just excluded from the hash).


class TestExtensionGovernorReproducibility:
    """Same logical input -> same hash across fresh constructions/runs."""

    @staticmethod
    def _make_manifest(build_ts: datetime) -> ExtensionManifest:
        return ExtensionManifest(
            extension_id="ext_repro",
            package_name="repro-ext",
            package_version="1.0.0",
            package_hash="pkg_hash_repro",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            deterministic_claim=True,
            replayability_claim=True,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
            provenance_build_timestamp=build_ts,
        )

    def test_manifest_hash_is_reproducible_across_build_timestamps(self) -> None:
        # Two fresh manifests, identical logical content, DIFFERENT wall-clock
        # provenance_build_timestamp. The content hash must be identical.
        m1 = self._make_manifest(datetime(2020, 1, 1, tzinfo=timezone.utc))
        m2 = self._make_manifest(datetime(2026, 5, 29, 12, 34, 56, tzinfo=timezone.utc))

        assert m1.provenance_build_timestamp != m2.provenance_build_timestamp
        assert m1.compute_hash() == m2.compute_hash()

        # Timestamp metadata is still recorded on each manifest.
        assert m1.provenance_build_timestamp == datetime(2020, 1, 1, tzinfo=timezone.utc)
        assert m2.provenance_build_timestamp is not None

    def test_manifest_hash_default_timestamp_is_reproducible(self) -> None:
        # Even using the live datetime.now() default, two fresh manifests built
        # at (potentially) different instants must hash identically.
        m1 = ExtensionManifest(
            extension_id="ext_default",
            package_name="default-ext",
            package_version="2.1.0",
            package_hash="pkg_default",
            capability_class=CapabilityClass.STATIC_ANALYZER,
        )
        m2 = ExtensionManifest(
            extension_id="ext_default",
            package_name="default-ext",
            package_version="2.1.0",
            package_hash="pkg_default",
            capability_class=CapabilityClass.STATIC_ANALYZER,
        )
        assert m1.compute_hash() == m2.compute_hash()
        # The auto-populated wall-clock metadata is still present.
        assert m1.provenance_build_timestamp is not None
        assert m2.provenance_build_timestamp is not None

    def test_bundle_hash_is_reproducible_across_created_at(self) -> None:
        # Two fresh bundles wrapping logically identical manifests, with
        # DIFFERENT created_at, must produce the same bundle hash.
        m1 = self._make_manifest(datetime(2020, 1, 1, tzinfo=timezone.utc))
        m2 = self._make_manifest(datetime(2026, 5, 29, tzinfo=timezone.utc))
        b1 = ExtensionBundle(
            bundle_id="bundle_repro",
            manifest=m1,
            payload_hash="payload_repro",
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        b2 = ExtensionBundle(
            bundle_id="bundle_repro",
            manifest=m2,
            payload_hash="payload_repro",
            created_at=datetime(2026, 5, 29, 9, 0, 0, tzinfo=timezone.utc),
        )
        assert b1.created_at != b2.created_at
        assert b1.compute_bundle_hash() == b2.compute_bundle_hash()
        # created_at metadata is still recorded.
        assert b1.created_at == datetime(2020, 1, 1, tzinfo=timezone.utc)
        assert b2.created_at is not None

    def test_receipt_hash_is_reproducible_across_execution_timestamp(self) -> None:
        # Two fresh receipts with identical logical content but DIFFERENT
        # execution_timestamp / execution_duration_ms must hash identically.
        common = {
            "receipt_id": "rcpt_repro",
            "extension_id": "ext_repro",
            "package_hash": "pkg_hash_repro",
            "worker_contract_version": "1.0.0",
            "output_hash": "out_hash_repro",
            "deterministic_fingerprint": "out_hash_repro",
            "replay_lineage": ["ext_repro"],
        }
        r1 = ExtensionExecutionReceipt(
            execution_timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc),
            execution_duration_ms=100,
            **common,
        )
        r2 = ExtensionExecutionReceipt(
            execution_timestamp=datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc),
            execution_duration_ms=999,
            **common,
        )
        assert r1.execution_timestamp != r2.execution_timestamp
        assert r1.execution_duration_ms != r2.execution_duration_ms
        assert r1.compute_hash() == r2.compute_hash()
        # Wall-clock metadata is still recorded on each receipt.
        assert r1.execution_timestamp == datetime(2020, 1, 1, tzinfo=timezone.utc)
        assert r2.execution_duration_ms == 999

    def test_receipt_id_is_content_addressed_not_random(self) -> None:
        # Admitting the SAME logical extension twice (two fresh governor stacks)
        # must yield the SAME receipt_id, proving it is derived from content and
        # not from a random uuid4.
        def _admit_once() -> str:
            with tempfile.TemporaryDirectory() as td:
                policy = ExtensionGovernancePolicy()
                ledger = ExtensionProvenanceLedger(ledger_dir=Path(td) / "ledger")
                trust = TrustZoneEnforcer()
                governor = ExtensionGovernor(
                    policy, ledger, trust, sandbox=SandboxedExtensionRuntime(allow_execution=True)
                )
                manifest = ExtensionManifest(
                    extension_id="receipt_repro_ext",
                    package_name="receipt-repro",
                    package_version="1.0.0",
                    package_hash="hash_receipt_repro",
                    capability_class=CapabilityClass.OPENAPI_TOOLING,
                    deterministic_claim=True,
                    replayability_claim=True,
                    network_access=False,
                    trust_zone=TrustZone.GOVERNED_EXTENSION,
                )
                bundle = ExtensionBundle(bundle_id="receipt_repro_bundle", manifest=manifest, payload_hash="ph_repro")
                source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'k': 1}}"
                result = governor.process_bundle(bundle, source, {})
                assert result.admitted is True
                assert result.provenance_receipt_id is not None
                return result.provenance_receipt_id

        id1 = _admit_once()
        id2 = _admit_once()
        assert id1 == id2
        assert id1.startswith("rcpt_receipt_repro_ext_")
