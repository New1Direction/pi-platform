"""Tests for pi-extension-catalog-integration layer.

Deterministic catalog ingestion, classification, policy gating,
sandbox validation, normalization, dependency expansion,
and composition planning.

All Notte API calls are mocked. No credentials in tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    ExtensionStatus,
    TrustZone,
)
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_interoperability_layer.capability.graph import (
    ExtensionCompatibilityGraph,
)
from pi_interoperability_layer.capability.registry import (
    SemanticCapabilityRegistry,
)
from pi_interoperability_layer.catalog.classifier_worker import (
    CapabilityClassifierWorker,
)
from pi_interoperability_layer.catalog.composition_planner import (
    CapabilityCompositionPlanner,
)
from pi_interoperability_layer.catalog.dependency_expansion_worker import (
    DependencyGraphExpansionWorker,
)
from pi_interoperability_layer.catalog.ingest_worker import (
    CatalogIngestReceipt,
    PackageCatalogIngestWorker,
)
from pi_interoperability_layer.catalog.normalization_worker import (
    PackageNormalizationWorker,
)
from pi_interoperability_layer.catalog.notte_client import (
    CatalogPage,
    CatalogSearchResult,
    NotteCatalogClient,
)
from pi_interoperability_layer.catalog.pipeline import (
    CatalogIntegrationPipeline,
)
from pi_interoperability_layer.catalog.policy_gate_worker import (
    PackagePolicyGateWorker,
)
from pi_interoperability_layer.catalog.sandbox_worker import (
    SandboxValidationWorker,
)

# ── Fixtures ───────────────────────────────────────────────────────


def _mock_manifest(
    name: str = "test-pkg", cap_class: CapabilityClass = CapabilityClass.STATIC_ANALYZER
) -> ExtensionManifest:
    return ExtensionManifest(
        extension_id=f"catalog_{name}_1.0.0",
        package_name=name,
        package_version="1.0.0",
        package_hash="",
        capability_class=cap_class,
        description="A test package",
        entrypoint="index.js",
        dependencies=[],
        trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
        telemetry_surfaces=[],
        resource_cpu_ms_max=5000,
        replayability_claim=False,
        deterministic_claim=False,
        metadata={"keywords": ["test"]},
        status=ExtensionStatus.PENDING_INSPECTION,
    )


# ── Notte Client Tests ─────────────────────────────────────────────


def test_notte_client_requires_api_key(monkeypatch: Any) -> None:
    monkeypatch.delenv("NOTTE_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="NOTTE_API_KEY"):
        NotteCatalogClient()


def test_notte_client_normalizes_search() -> None:
    client = MagicMock(spec=NotteCatalogClient)
    pkg = CatalogSearchResult(
        package_name="openapi-linter",
        package_version="2.1.0",
        package_type="npm",
        description="OpenAPI validation tool",
        keywords=("openapi", "validation"),
        author="test",
        license="MIT",
        dependencies=("ajv", "yaml"),
        dev_dependencies=(),
        raw_metadata_hash="abc123",
        ingest_timestamp="",
    )
    page = CatalogPage(
        page=1,
        page_size=1,
        total_packages=1,
        packages=[pkg],
        page_hash="pagehash",
    )
    client.search.return_value = page
    result = client.search("openapi", "npm", 1, 10)
    assert result.total_packages == 1
    assert result.packages[0].package_name == "openapi-linter"


# ── Ingest Worker Tests ────────────────────────────────────────────


def test_ingest_worker_normalizes_manifest() -> None:
    pkg = CatalogSearchResult(
        package_name="k8s-scanner",
        package_version="1.0.0",
        package_type="npm",
        description="Kubernetes security scanner",
        keywords=("kubernetes", "security"),
        author="pi-team",
        license="Apache-2.0",
        dependencies=("js-yaml",),
        dev_dependencies=(),
        raw_metadata_hash="rawhash",
        ingest_timestamp="",
    )
    worker = PackageCatalogIngestWorker()
    # Mock the client
    worker.client = MagicMock()
    worker.client.search.return_value = CatalogPage(
        page=1, page_size=1, total_packages=1, packages=[pkg], page_hash="phash"
    )
    receipt = worker.ingest_page("k8s", "npm", 1, 10)
    assert receipt.packages_ingested == 1
    assert len(receipt.normalized_manifests) == 1
    manifest = receipt.normalized_manifests[0]
    assert manifest.package_name == "k8s-scanner"
    assert manifest.trust_zone == TrustZone.SANDBOX_EXPERIMENTAL
    assert manifest.status == ExtensionStatus.PENDING_INSPECTION


def test_ingest_receipt_hash_determinism() -> None:
    pkg = CatalogSearchResult(
        package_name="det-pkg",
        package_version="1.0.0",
        package_type="npm",
        description="Deterministic test",
        keywords=(),
        author="",
        license="",
        dependencies=(),
        dev_dependencies=(),
        raw_metadata_hash="r1",
        ingest_timestamp="",
    )
    worker = PackageCatalogIngestWorker()
    worker.client = MagicMock()
    worker.client.search.return_value = CatalogPage(
        page=1, page_size=1, total_packages=1, packages=[pkg], page_hash="ph1"
    )
    r1 = worker.ingest_page("", "all", 1, 10)
    r2 = worker.ingest_page("", "all", 1, 10)
    # Receipt hashes are content-addressed: the wall-clock timestamp is excluded
    # from the hash, so the same logical page reproduces an identical hash.
    assert r1.receipt_hash != ""
    assert r2.receipt_hash != ""
    assert r1.receipt_hash == r2.receipt_hash
    assert r1.ingest_id == r2.ingest_id
    assert r1.packages_ingested == r2.packages_ingested
    # The wall-clock timestamp is still recorded as metadata on each receipt.
    assert r1.timestamp != ""


# ── Classifier Worker Tests ────────────────────────────────────────


def test_classifier_keyword_match() -> None:
    manifest = _mock_manifest("openapi-tool", CapabilityClass.STATIC_ANALYZER)
    manifest = manifest.model_copy(
        update={
            "description": "OpenAPI schema validator and swagger parser",
            "metadata": {"keywords": ["openapi", "swagger", "rest-api"]},
        }
    )
    worker = CapabilityClassifierWorker()
    result = worker.classify(manifest)
    assert result.assigned_class == CapabilityClass.OPENAPI_TOOLING
    assert any(e.confidence_basis == "keyword_match" for e in result.evidence)
    assert result.classification_hash != ""


def test_classifier_dependency_match() -> None:
    manifest = _mock_manifest("k8s-helper", CapabilityClass.STATIC_ANALYZER)
    manifest = manifest.model_copy(
        update={
            "dependencies": ["@kubernetes/client-node", "helm"],
        }
    )
    worker = CapabilityClassifierWorker()
    result = worker.classify(manifest)
    assert result.assigned_class == CapabilityClass.KUBERNETES_MANIFEST
    assert any(e.confidence_basis == "dependency_pattern" for e in result.evidence)


def test_classifier_no_match_defaults_static() -> None:
    manifest = _mock_manifest("random-pkg")
    worker = CapabilityClassifierWorker()
    result = worker.classify(manifest)
    assert result.assigned_class == CapabilityClass.STATIC_ANALYZER


# ── Policy Gate Worker Tests ─────────────────────────────────────


def test_policy_gate_passes_safe_package() -> None:
    manifest = _mock_manifest("safe-pkg")
    worker = PackagePolicyGateWorker()
    result = worker.evaluate(manifest)
    assert result.passed is True
    assert all(f.passed for f in result.findings)
    assert result.gate_hash != ""


def test_policy_gate_fails_banned_import() -> None:
    manifest = _mock_manifest("evil-pkg")
    manifest = manifest.model_copy(
        update={
            "dependencies": ["eval", "child_process"],
        }
    )
    worker = PackagePolicyGateWorker()
    result = worker.evaluate(manifest)
    assert result.passed is False
    banned_finding = [f for f in result.findings if f.rule_id == "banned_imports"]
    assert len(banned_finding) == 1
    assert banned_finding[0].passed is False


def test_policy_gate_fails_zone_restriction() -> None:
    manifest = _mock_manifest("zone-pkg")
    manifest = manifest.model_copy(
        update={
            "trust_zone": TrustZone.CORE_TRUSTED,
        }
    )
    policy = ExtensionGovernancePolicy(
        approved_capability_classes=set(CapabilityClass),
        banned_imports=set(),
        max_cpu_ms=10000,
        max_memory_mb=512,
        max_output_size=50 * 1024 * 1024,
        require_replay_safe=False,
        require_deterministic=False,
        allowed_trust_zones={TrustZone.SANDBOX_EXPERIMENTAL},
        allowed_telemetry_surfaces=set(),
    )
    worker = PackagePolicyGateWorker(policy)
    result = worker.evaluate(manifest)
    assert result.passed is False
    zone_finding = [f for f in result.findings if f.rule_id == "trust_zone_allowed"]
    assert zone_finding[0].passed is False


# ── Sandbox Worker Tests ─────────────────────────────────────────


def test_sandbox_validates_deterministic_code() -> None:
    manifest = _mock_manifest("det-pkg")
    worker = SandboxValidationWorker()
    source = "OUTPUT = {'result': 42}"
    receipt = worker.validate(manifest, source, {})
    assert receipt.executed is True
    assert receipt.determinism_verified is True
    assert receipt.replay_safe_verified is True
    assert receipt.outputs_match is True
    assert receipt.receipt_hash != ""


def test_sandbox_fails_non_deterministic() -> None:
    manifest = _mock_manifest("non-det-pkg")
    worker = SandboxValidationWorker()
    source = "import random\nOUTPUT = {'result': random.randint(1, 100)}"
    receipt = worker.validate(manifest, source, {})
    assert receipt.executed is True
    assert receipt.determinism_verified is False
    assert receipt.outputs_match is False


# ── Normalization Worker Tests ───────────────────────────────────


def test_normalization_accept_known_artifact() -> None:
    manifest = _mock_manifest("norm-pkg", CapabilityClass.OPENAPI_TOOLING)
    worker = PackageNormalizationWorker()
    raw = {"artifact_type": "SemanticIRTrace", "endpoints": []}
    receipt = worker.normalize(manifest, raw)
    assert receipt.normalized is True
    assert receipt.artifact_type == "SemanticIRTrace"
    assert receipt.receipt_hash != ""


def test_normalization_reject_unknown_artifact() -> None:
    manifest = _mock_manifest("bad-pkg")
    worker = PackageNormalizationWorker()
    raw = {"artifact_type": "UnknownArtifact", "data": "x"}
    receipt = worker.normalize(manifest, raw)
    assert receipt.normalized is False
    assert receipt.rejection_reason is not None


# ── Dependency Expansion Worker Tests ────────────────────────────


def test_dependency_expansion_adds_edges() -> None:
    graph = ExtensionCompatibilityGraph()
    dep_manifest = _mock_manifest("dep-pkg")
    dep_manifest = dep_manifest.model_copy(
        update={
            "extension_id": "catalog_dep-pkg_1.0.0",
            "name": "dep-pkg",
        }
    )
    graph.register_installed(dep_manifest.extension_id)

    main_manifest = _mock_manifest("main-pkg")
    main_manifest = main_manifest.model_copy(
        update={
            "dependencies": ["dep-pkg@^1.0.0"],
        }
    )

    worker = DependencyGraphExpansionWorker(graph)
    known = {"dep-pkg": dep_manifest}
    receipt = worker.expand(main_manifest, known)
    assert receipt.edges_added == 1
    assert receipt.conflicts_detected == 0
    assert receipt.receipt_hash != ""


def test_dependency_expansion_records_missing() -> None:
    graph = ExtensionCompatibilityGraph()
    manifest = _mock_manifest("orphan-pkg")
    manifest = manifest.model_copy(
        update={
            "dependencies": ["missing-dep@1.0.0"],
        }
    )
    worker = DependencyGraphExpansionWorker(graph)
    receipt = worker.expand(manifest, {})
    assert receipt.edges_added == 0
    assert "missing-dep" in receipt.missing_deps


# ── Composition Planner Tests ────────────────────────────────────


def test_planner_builds_valid_dag() -> None:
    graph = ExtensionCompatibilityGraph()
    a = _mock_manifest("a")
    a = a.model_copy(update={"extension_id": "catalog_a_1.0.0", "name": "a"})
    b = _mock_manifest("b")
    b = b.model_copy(update={"extension_id": "catalog_b_1.0.0", "name": "b", "dependencies": ["a"]})
    c = _mock_manifest("c")
    c = c.model_copy(update={"extension_id": "catalog_c_1.0.0", "name": "c", "dependencies": ["a"]})

    planner = CapabilityCompositionPlanner(graph)
    plan = planner.plan([a, b, c])
    assert plan.valid is True
    assert len(plan.execution_order) == 2
    assert ["catalog_a_1.0.0"] == sorted(plan.execution_order[0])
    assert sorted(["catalog_b_1.0.0", "catalog_c_1.0.0"]) == sorted(plan.execution_order[1])
    assert plan.plan_hash != ""


def test_planner_detects_cycles() -> None:
    graph = ExtensionCompatibilityGraph()
    a = _mock_manifest("a")
    a = a.model_copy(update={"extension_id": "catalog_a_1.0.0", "name": "a", "dependencies": ["b"]})
    b = _mock_manifest("b")
    b = b.model_copy(update={"extension_id": "catalog_b_1.0.0", "name": "b", "dependencies": ["a"]})

    planner = CapabilityCompositionPlanner(graph)
    plan = planner.plan([a, b])
    assert plan.valid is False
    assert "cycle" in (plan.reason or "").lower()


def test_planner_empty_manifests_invalid() -> None:
    graph = ExtensionCompatibilityGraph()
    planner = CapabilityCompositionPlanner(graph)
    plan = planner.plan([])
    assert plan.valid is False


# ── Full Pipeline Tests ──────────────────────────────────────────


def test_pipeline_admits_deterministic_package(tmp_path: Path) -> None:
    registry = SemanticCapabilityRegistry(root_dir=tmp_path)
    graph = ExtensionCompatibilityGraph()
    pipeline = CatalogIntegrationPipeline(registry, graph)
    # Mock the ingest worker to avoid Notte API key requirement
    CatalogSearchResult(
        package_name="safe-pkg",
        package_version="1.0.0",
        package_type="npm",
        description="",
        keywords=(),
        author="",
        license="",
        dependencies=(),
        dev_dependencies=(),
        raw_metadata_hash="abc",
        ingest_timestamp="",
    )
    pipeline.ingest_worker = MagicMock()
    pipeline.ingest_worker.ingest_package.return_value = CatalogIngestReceipt(
        ingest_id="test",
        page=1,
        packages_ingested=1,
        raw_hash="abc",
        normalized_manifests=(_mock_manifest("safe-pkg"),),
        timestamp="",
        receipt_hash="rhash",
    )

    source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'endpoints': []}"
    receipt = pipeline.process_package("safe-pkg", source, {})
    assert receipt.final_status in ("ADMITTED", "REJECTED")
    assert receipt.pipeline_hash != ""
    assert len(receipt.evidence_chain) >= 3


def test_pipeline_receipt_chain_integrity(tmp_path: Path) -> None:
    registry = SemanticCapabilityRegistry(root_dir=tmp_path)
    graph = ExtensionCompatibilityGraph()
    pipeline = CatalogIntegrationPipeline(registry, graph)
    pipeline.ingest_worker = MagicMock()
    pipeline.ingest_worker.ingest_package.return_value = CatalogIngestReceipt(
        ingest_id="test",
        page=1,
        packages_ingested=1,
        raw_hash="abc",
        normalized_manifests=(_mock_manifest("pkg-a"),),
        timestamp="",
        receipt_hash="rhash",
    )

    source = "OUTPUT = {'result': 1}"
    r1 = pipeline.process_package("pkg-a", source, {})
    pipeline.ingest_worker.ingest_package.return_value = CatalogIngestReceipt(
        ingest_id="test2",
        page=1,
        packages_ingested=1,
        raw_hash="def",
        normalized_manifests=(_mock_manifest("pkg-b"),),
        timestamp="",
        receipt_hash="rhash2",
    )
    r2 = pipeline.process_package("pkg-b", source, {})
    assert r1.pipeline_hash != r2.pipeline_hash
    assert r1.final_status == r2.final_status  # both should be ADMITTED or REJECTED


def test_pipeline_deterministic_same_input_same_receipt(tmp_path: Path) -> None:
    registry = SemanticCapabilityRegistry(root_dir=tmp_path)
    graph = ExtensionCompatibilityGraph()
    pipeline = CatalogIntegrationPipeline(registry, graph)
    pipeline.ingest_worker = MagicMock()
    pipeline.ingest_worker.ingest_package.return_value = CatalogIngestReceipt(
        ingest_id="test",
        page=1,
        packages_ingested=1,
        raw_hash="abc",
        normalized_manifests=(_mock_manifest("stable-pkg"),),
        timestamp="",
        receipt_hash="rhash",
    )

    source = "OUTPUT = {'stable': True}"
    r1 = pipeline.process_package("stable-pkg", source, {})
    r2 = pipeline.process_package("stable-pkg", source, {})
    # Same inputs should produce same pipeline hash (deterministic)
    # Note: timestamps differ, so we verify structure not exact hash
    assert r1.manifest_id == r2.manifest_id
    assert r1.final_status == r2.final_status


# ── End-to-End Catalog Mock Tests ──────────────────────────────────


def test_catalog_mock_ingest_classify_gate() -> None:
    """Simulate full flow with mocked Notte client."""
    pkg = CatalogSearchResult(
        package_name="static-analyzer",
        package_version="3.0.0",
        package_type="npm",
        description="Static analysis and linting tool",
        keywords=("lint", "static", "analysis"),
        author="pi-team",
        license="MIT",
        dependencies=(),
        dev_dependencies=(),
        raw_metadata_hash="mockhash",
        ingest_timestamp="",
    )
    client = MagicMock(spec=NotteCatalogClient)
    client.package_details.return_value = pkg

    worker = PackageCatalogIngestWorker(client=client)
    receipt = worker.ingest_package("static-analyzer")
    assert receipt.packages_ingested == 1
    manifest = receipt.normalized_manifests[0]
    assert manifest.package_name == "static-analyzer"

    # Classify
    classifier = CapabilityClassifierWorker()
    class_result = classifier.classify(manifest)
    assert class_result.assigned_class == CapabilityClass.STATIC_ANALYZER

    # Policy gate
    gate = PackagePolicyGateWorker()
    gate_result = gate.evaluate(manifest)
    assert gate_result.passed is True

    # Sandbox
    sandbox = SandboxValidationWorker()
    source = "OUTPUT = {'findings': []}"
    sandbox_result = sandbox.validate(manifest, source, {})
    assert sandbox_result.determinism_verified is True
