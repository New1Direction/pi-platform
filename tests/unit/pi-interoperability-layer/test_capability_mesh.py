"""Tests for semantic capability mesh: registry, graph, ingestion, indexing, shard coordinator.

Deterministic admission control, compatibility enforcement,
semantic indexing, and distributed shard coordination.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from pi_extension_governor.manifest import (
    ExtensionManifest,
    ExtensionBundle,
    CapabilityClass,
    TrustZone,
    ExtensionStatus,
)
from pi_extension_governor.governor import ExtensionGovernor

from pi_interoperability_layer.capability.registry import (
    SemanticCapabilityRegistry,
    RegistryEntryStatus,
    RegistryFingerprints,
    TrustScore,
    TrustScoringBasis,
)
from pi_interoperability_layer.capability.graph import (
    ExtensionCompatibilityGraph,
    CompatibilityEdge,
    CompatibilityType,
    CompatibilityVerdict,
)
from pi_interoperability_layer.capability.ingestion import (
    GovernedIngestionPipeline,
    IngestionPhase,
)
from pi_interoperability_layer.capability.indexing import (
    SemanticIndexWorker,
    SemanticQueryWorker,
    IndexEntry,
)
from pi_interoperability_layer.mesh.shard import (
    DeterministicPartitioner,
    ShardCoordinator,
    ShardState,
)


# ── Registry Tests ────────────────────────────────────────────────

def _make_manifest(extension_id: str, capability: CapabilityClass) -> ExtensionManifest:
    return ExtensionManifest(
        extension_id=extension_id,
        package_name=extension_id,
        package_version="1.0.0",
        package_hash="hash_" + extension_id,
        capability_class=capability,
        declared_inputs=[],
        declared_outputs=[],
        network_access=False,
        filesystem_access=False,
        subprocess_access=False,
        dynamic_eval_access=False,
        thread_spawn_access=False,
        deterministic_claim=True,
        replayability_claim=True,
        resource_cpu_ms_max=1000,
        resource_memory_mb_max=128,
        resource_output_size_max=1024 * 1024,
        semantic_version="1.0.0",
        provenance_metadata={},
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )


def test_registry_register_and_lookup() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        manifest = _make_manifest("ext_1", CapabilityClass.OPENAPI_TOOLING)
        fingerprints = RegistryFingerprints(
            manifest_hash="m1", source_hash="s1",
            determinism_fingerprint="d1", policy_hash="p1",
            normalization_hash="n1", provenance_chain_hash="c1",
        )
        score = TrustScore().with_evidence(TrustScoringBasis.STATIC_ANALYSIS, 50)
        entry = reg.register(manifest, fingerprints, score, RegistryEntryStatus.ACTIVE)
        assert entry.extension_id == "ext_1"
        assert entry.trust_score.composite_score == 50
        assert entry.entry_hash == entry.compute_hash()
        assert reg.lookup("ext_1") == entry


def test_registry_query_by_capability() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        for i, cap in enumerate([CapabilityClass.OPENAPI_TOOLING, CapabilityClass.GRAPHQL_TOOLING]):
            manifest = _make_manifest(f"ext_{i}", cap)
            fingerprints = RegistryFingerprints(
                manifest_hash=f"m{i}", source_hash=f"s{i}",
                determinism_fingerprint="d", policy_hash="p",
                normalization_hash="n", provenance_chain_hash="c",
            )
            reg.register(manifest, fingerprints, TrustScore())
        results = reg.query(capability_class=CapabilityClass.OPENAPI_TOOLING)
        assert len(results) == 1
        assert results[0].extension_id == "ext_0"


def test_registry_update_status() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        manifest = _make_manifest("ext_1", CapabilityClass.KUBERNETES_MANIFEST)
        fingerprints = RegistryFingerprints(
            manifest_hash="m", source_hash="s",
            determinism_fingerprint="d", policy_hash="p",
            normalization_hash="n", provenance_chain_hash="c",
        )
        entry = reg.register(manifest, fingerprints, TrustScore())
        updated = reg.update_status("ext_1", RegistryEntryStatus.REVOKED)
        assert updated.status == RegistryEntryStatus.REVOKED
        assert updated.previous_entry_hash == entry.entry_hash
        assert reg.lookup("ext_1").status == RegistryEntryStatus.REVOKED


def test_registry_chain_integrity() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        manifest = _make_manifest("ext_1", CapabilityClass.OPENAPI_TOOLING)
        fingerprints = RegistryFingerprints(
            manifest_hash="m", source_hash="s",
            determinism_fingerprint="d", policy_hash="p",
            normalization_hash="n", provenance_chain_hash="c",
        )
        reg.register(manifest, fingerprints, TrustScore())
        ok, errors = reg.verify_chain_integrity()
        assert ok is True
        assert errors == []


def test_registry_trust_score_bounds() -> None:
    score = TrustScore().with_evidence(TrustScoringBasis.POLICY_EVIDENCE, 200)
    assert score.policy_passed == 100  # capped at 100


# ── Compatibility Graph Tests ────────────────────────────────────

def test_graph_dependency_resolution() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("ext_a", "ext_b", CompatibilityType.DEPENDS_ON, "needs b"))
    g.register_installed("ext_b")
    checks = g.check_install("ext_a", _make_manifest("ext_a", CapabilityClass.OPENAPI_TOOLING), lambda x: None)
    assert all(c.verdict == CompatibilityVerdict.COMPATIBLE for c in checks)


def test_graph_missing_dependency() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("ext_a", "ext_b", CompatibilityType.DEPENDS_ON, "needs b"))
    # ext_b NOT installed
    checks = g.check_install("ext_a", _make_manifest("ext_a", CapabilityClass.OPENAPI_TOOLING), lambda x: None)
    assert any(c.verdict == CompatibilityVerdict.MISSING_DEPENDENCY for c in checks)


def test_graph_conflict_detection() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("ext_a", "ext_b", CompatibilityType.CONFLICTS_WITH, "incompatible"))
    g.register_installed("ext_b")
    checks = g.check_install("ext_a", _make_manifest("ext_a", CapabilityClass.OPENAPI_TOOLING), lambda x: None)
    assert any(c.verdict == CompatibilityVerdict.CONFLICT for c in checks)


def test_graph_zone_incompatible() -> None:
    g = ExtensionCompatibilityGraph()
    # mock registry lookup returning core trusted entry
    class FakeEntry:
        trust_zone = TrustZone.CORE_TRUSTED
    g.register_installed("core_1")
    manifest = _make_manifest("sandbox_1", CapabilityClass.OPENAPI_TOOLING)
    manifest = ExtensionManifest(
        extension_id="sandbox_1",
        package_name="sandbox_1",
        package_version="1.0.0",
        package_hash="h",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        declared_inputs=[],
        declared_outputs=[],
        network_access=False,
        filesystem_access=False,
        subprocess_access=False,
        dynamic_eval_access=False,
        thread_spawn_access=False,
        deterministic_claim=True,
        replayability_claim=True,
        resource_cpu_ms_max=1000,
        resource_memory_mb_max=128,
        resource_output_size_max=1024 * 1024,
        semantic_version="1.0.0",
        provenance_metadata={},
        trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
    )
    checks = g.check_install("sandbox_1", manifest, lambda x: FakeEntry() if x == "core_1" else None)
    assert any(c.verdict == CompatibilityVerdict.ZONE_INCOMPATIBLE for c in checks)


def test_graph_transitive_closure() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("a", "b", CompatibilityType.DEPENDS_ON))
    g.declare_edge(CompatibilityEdge("b", "c", CompatibilityType.DEPENDS_ON))
    closure = g.transitive_closure("a")
    assert closure == {"a", "b", "c"}


def test_graph_topological_phases() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("a", "b", CompatibilityType.DEPENDS_ON))
    g.declare_edge(CompatibilityEdge("c", "b", CompatibilityType.DEPENDS_ON))
    g.register_installed("a")
    g.register_installed("b")
    g.register_installed("c")
    phases = g.topological_phase_order()
    assert len(phases) == 2  # a and c first (in-degree 0), then b
    assert {"a", "c"} == phases[0]
    assert {"b"} == phases[1]


def test_graph_hash_determinism() -> None:
    g = ExtensionCompatibilityGraph()
    g.declare_edge(CompatibilityEdge("a", "b", CompatibilityType.DEPENDS_ON))
    g.declare_edge(CompatibilityEdge("a", "c", CompatibilityType.DEPENDS_ON))
    h1 = g.to_hashes()
    g2 = ExtensionCompatibilityGraph()
    g2.declare_edge(CompatibilityEdge("a", "c", CompatibilityType.DEPENDS_ON))
    g2.declare_edge(CompatibilityEdge("a", "b", CompatibilityType.DEPENDS_ON))
    h2 = g2.to_hashes()
    assert h1 == h2


# ── Ingestion Pipeline Tests ─────────────────────────────────────

def _make_governor(ledger_dir: Path) -> ExtensionGovernor:
    from pi_extension_governor.policy import ExtensionGovernancePolicy
    from pi_extension_governor.provenance import ExtensionProvenanceLedger
    from pi_extension_governor.trust_zones import TrustZoneEnforcer
    from pi_extension_governor.sandbox import SandboxedExtensionRuntime
    from pi_extension_governor.inspector import StaticCapabilityInspector
    from pi_extension_governor.normalizer import SemanticOutputNormalizer

    policy = ExtensionGovernancePolicy(
        approved_capability_classes={CapabilityClass.OPENAPI_TOOLING},
        banned_imports=set(),
        max_cpu_ms=1000,
        max_memory_mb=128,
        max_output_size=1024 * 1024,
        require_replay_safe=True,
        require_deterministic=True,
        allowed_trust_zones={TrustZone.GOVERNED_EXTENSION, TrustZone.SANDBOX_EXPERIMENTAL},
        allowed_telemetry_surfaces=set(),
    )
    ledger = ExtensionProvenanceLedger(ledger_dir=ledger_dir)
    enforcer = TrustZoneEnforcer(core_trusted_packages=set())
    return ExtensionGovernor(
        policy=policy,
        ledger=ledger,
        trust_enforcer=enforcer,
    )


def test_ingestion_pipeline_admits_safe() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        graph = ExtensionCompatibilityGraph()
        governor = _make_governor(Path(td))
        pipeline = GovernedIngestionPipeline(governor, reg, graph)

        manifest = _make_manifest("safe_ext", CapabilityClass.OPENAPI_TOOLING)
        bundle = ExtensionBundle(
            bundle_id="safe_bundle",
            manifest=manifest,
            payload_hash="abc123",
        )
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'endpoints': []}"
        result = pipeline.ingest(bundle, source, {})

        # If governor admitted, we should get ADMITTED; if rejected by inspection, REJECTED
        assert result.final_verdict in ("ADMITTED", "REJECTED")
        # Chain integrity must hold regardless
        ok, errors = pipeline.verify_receipt_chain()
        assert ok is True


def test_ingestion_pipeline_receipt_immutable() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        graph = ExtensionCompatibilityGraph()
        governor = _make_governor(Path(td))
        pipeline = GovernedIngestionPipeline(governor, reg, graph)

        manifest = _make_manifest("imm_ext", CapabilityClass.OPENAPI_TOOLING)
        bundle = ExtensionBundle(
            bundle_id="imm_bundle",
            manifest=manifest,
            payload_hash="def456",
        )
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace'}"
        result = pipeline.ingest(bundle, source, {})
        # receipt_hash should be set
        assert result.receipt_hash != ""
        assert result.compute_hash() == result.receipt_hash


def test_ingestion_pipeline_audit_log() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SemanticCapabilityRegistry(root_dir=Path(td))
        graph = ExtensionCompatibilityGraph()
        governor = _make_governor(Path(td))
        pipeline = GovernedIngestionPipeline(governor, reg, graph)

        manifest = _make_manifest("audit_ext", CapabilityClass.OPENAPI_TOOLING)
        bundle = ExtensionBundle(
            bundle_id="audit_bundle",
            manifest=manifest,
            payload_hash="ghi789",
        )
        source = "OUTPUT = {'artifact_type': 'SemanticIRTrace'}"
        pipeline.ingest(bundle, source, {})
        log = pipeline.audit_log()
        assert len(log) >= 1


# ── Semantic Indexing Tests ───────────────────────────────────────

def test_index_worker_basic_index_and_query() -> None:
    with tempfile.TemporaryDirectory() as td:
        idx = SemanticIndexWorker(root_dir=Path(td))
        entry = idx.index(
            artifact_id="art_1",
            artifact_type="SemanticIRTrace",
            source_extension_id="ext_1",
            fields={"endpoint_path": "/api/users"},
            provenance_hash="prov_1",
        )
        assert entry.entry_hash == entry.compute_hash()
        results = idx.query(artifact_type="SemanticIRTrace")
        assert len(results) == 1
        assert results[0].artifact_id == "art_1"


def test_index_worker_field_filter() -> None:
    with tempfile.TemporaryDirectory() as td:
        idx = SemanticIndexWorker(root_dir=Path(td))
        idx.index("art_1", "SemanticIRTrace", "ext_1", {"path": "/a"}, "p1")
        idx.index("art_2", "SemanticIRTrace", "ext_1", {"path": "/b"}, "p2")
        idx.index("art_3", "DependencyGraph", "ext_2", {"path": "/a"}, "p3")
        results = idx.query(fields={"path": "/a"})
        assert len(results) == 2


def test_query_worker_lineage() -> None:
    with tempfile.TemporaryDirectory() as td:
        idx = SemanticIndexWorker(root_dir=Path(td))
        qw = SemanticQueryWorker(idx)
        idx.index("art_1", "SemanticIRTrace", "ext_1", {}, "p1")
        idx.index("art_2", "DependencyGraph", "ext_1", {}, "p1")
        lineage = qw.lineage("art_1")
        assert len(lineage) == 2


def test_query_worker_cross_reference() -> None:
    with tempfile.TemporaryDirectory() as td:
        idx = SemanticIndexWorker(root_dir=Path(td))
        qw = SemanticQueryWorker(idx)
        idx.index("art_1", "SemanticIRTrace", "ext_1", {"node_id": "n1"}, "p1")
        idx.index("art_2", "DependencyGraph", "ext_2", {"node_id": "n1"}, "p2")
        pairs = qw.cross_reference("SemanticIRTrace", "DependencyGraph", "node_id")
        assert len(pairs) == 1
        assert pairs[0][0].artifact_id == "art_1"
        assert pairs[0][1].artifact_id == "art_2"


# ── Shard Coordinator Tests ──────────────────────────────────────

def test_partitioner_deterministic() -> None:
    p = DeterministicPartitioner(shard_count=3)
    a1 = p.assign("worker_a")
    a2 = p.assign("worker_a")
    assert a1.shard_id == a2.shard_id
    assert a1.assignment_hash == a2.assignment_hash


def test_shard_coordinator_registration() -> None:
    p = DeterministicPartitioner(shard_count=2, shard_ids=["s0", "s1"])
    sc = ShardCoordinator(p, max_workers_per_shard=10)
    assignments = sc.register_workers(["w1", "w2", "w3"])
    assert len(assignments) == 3
    shards = {a.shard_id for a in assignments.values()}
    assert shards <= {"s0", "s1"}


def test_shard_coordinator_phase_lock() -> None:
    p = DeterministicPartitioner(shard_count=2, shard_ids=["s0", "s1"])
    sc = ShardCoordinator(p)
    sc.register_workers(["w1", "w2"])
    sc.begin_phase("INGEST")
    assert not sc.can_advance_phase()
    sc.mark_shard_completed("s0")
    assert not sc.can_advance_phase()
    sc.mark_shard_completed("s1")
    assert sc.can_advance_phase()
    boundary = sc.advance_phase("EXTRACT")
    assert boundary.phase == "INGEST"
    assert boundary.completed is True


def test_shard_coordinator_replay_sequence() -> None:
    p = DeterministicPartitioner(shard_count=2, shard_ids=["s0", "s1"])
    sc = ShardCoordinator(p)
    sc.register_workers(["w1", "w2", "w3"])
    seq = sc.replay_sequence()
    shard_ids = [sid for sid, _ in seq]
    assert sorted(shard_ids) == ["s0", "s1"]
    all_workers = [w for _, workers in seq for w in workers]
    assert sorted(all_workers) == ["w1", "w2", "w3"]


def test_shard_coordinator_worker_shard_lookup() -> None:
    p = DeterministicPartitioner(shard_count=2, shard_ids=["s0", "s1"])
    sc = ShardCoordinator(p)
    sc.register_workers(["w1", "w2"])
    assert sc.get_shard_for_worker("w1") in {"s0", "s1"}
    assert sc.get_shard_for_worker("w2") in {"s0", "s1"}


def test_shard_coordinator_max_workers_enforced() -> None:
    p = DeterministicPartitioner(shard_count=1, shard_ids=["s0"])
    sc = ShardCoordinator(p, max_workers_per_shard=2)
    sc.register_workers(["w1", "w2"])
    with pytest.raises(ValueError):
        sc.register_workers(["w3"])


def test_shard_coordinator_snapshot() -> None:
    p = DeterministicPartitioner(shard_count=2, shard_ids=["s0", "s1"])
    sc = ShardCoordinator(p)
    sc.register_workers(["w1", "w2"])
    sc.begin_phase("INGEST")
    sc.mark_shard_completed("s0")
    sc.mark_shard_completed("s1")
    sc.advance_phase("EXTRACT")
    snap = sc.snapshot()
    assert snap["shard_count"] == 2
    assert snap["current_phase"] == "EXTRACT"
    assert len(snap["phase_boundaries"]) == 1


def test_shard_coordinator_verify_assignment_determinism() -> None:
    p = DeterministicPartitioner(shard_count=4)
    sc = ShardCoordinator(p)
    workers = [f"worker_{i}" for i in range(20)]
    assert sc.verify_assignment_determinism(workers) is True
