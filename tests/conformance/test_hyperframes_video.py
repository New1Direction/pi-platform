"""HyperFrames Video Extension Conformance Tests.

Tests for:
- DocumentationHyperFrameRenderer (architecture, governance, catalog, tests)
- InfrastructureReplayHyperFrameRenderer (ingestion, topology, drift, blast, governance)

All deterministic. No randomness.
"""

from __future__ import annotations

import os
import tempfile

from pi_connector_fabric.hyperframes_infra import InfrastructureReplayHyperFrameRenderer
from pi_connector_fabric.marketplace.governance import ConnectorMarketplaceRegistry
from pi_connector_fabric.replay.import_pipeline import DigitalTwinImport
from pi_connector_fabric.sdk.core import (
    ArtifactNormalizer,
    ConnectorExecutionFence,
    ConnectorSandboxPolicy,
    IngestionReceipt,
)
from pi_connector_fabric.topology.engine import (
    RiskPropagationTopology,
    UnifiedTopologyGraph,
)
from pi_event_fabric.governance.compiler import (
    Effect,
    GovernanceDecision,
)
from pi_interoperability_layer.hyperframes_docs import DocumentationHyperFrameRenderer

# ──────────────────────────────
#  Documentation Video Tests
# ──────────────────────────────


class TestDocumentationHyperFrames:
    def test_render_platform_architecture(self):
        renderer = DocumentationHyperFrameRenderer()
        layers = [
            {
                "layer_number": 1,
                "name": "Control Plane",
                "role": "Multi-tenant SaaS orchestration",
                "components": ["TenantRegistry", "QuotaManager", "AuditLog"],
                "invariants": ["No LLM", "Append-only"],
            },
            {
                "layer_number": 2,
                "name": "Execution Fabric",
                "role": "Shard-coordinated deterministic pipeline",
                "components": ["ShardRouter", "PipelineExecutor", "CheckpointStore"],
                "invariants": ["Deterministic ordering", "Replay-safe"],
            },
            {
                "layer_number": 3,
                "name": "Capability Marketplace",
                "role": "Explicit composition only",
                "components": ["Registry", "CompatibilityGraph", "TrustScorer"],
                "invariants": ["No autonomous agents", "Fail-closed"],
            },
        ]
        seq = renderer.render_platform_architecture(layers, title="PI Platform")
        assert seq.total_frames == 5  # overview + 3 layers + governance
        assert seq.sequence_hash != ""
        assert len(seq.frames) == 5
        assert all(f.frame_hash != "" for f in seq.frames)

    def test_architecture_deterministic_hash(self):
        renderer = DocumentationHyperFrameRenderer()
        layers = [
            {"layer_number": 1, "name": "L1", "role": "R", "components": ["A"], "invariants": ["I"]},
        ]
        seq1 = renderer.render_platform_architecture(layers)
        seq2 = renderer.render_platform_architecture(layers)
        assert seq1.sequence_hash == seq2.sequence_hash

    def test_render_governance_invariants(self):
        renderer = DocumentationHyperFrameRenderer()
        invariants = [
            {"id": "NO_LLM", "description": "No LLM inference in core", "enforcement": "static", "scope": "global"},
            {"id": "APPEND_ONLY", "description": "All state append-only", "enforcement": "static", "scope": "global"},
        ]
        seq = renderer.render_governance_invariants(invariants)
        assert seq.total_frames == 4  # title + 2 invariants + summary
        assert seq.frames[-1].frame_metadata.get("title") == "Invariant Summary"

    def test_render_connector_catalog(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            registry = ConnectorMarketplaceRegistry(path)
            # Register a fake manifest for testing
            from pi_connector_fabric.sdk.core import ConnectorCapabilityClass, ConnectorManifest, ConnectorSandboxPolicy

            m = ConnectorManifest(
                connector_id="test.v1",
                name="Test",
                version="1.0.0",
                description="Test connector",
                capability_classes=(ConnectorCapabilityClass.TOPOLOGY_READ,),
                sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
                target_systems=("test",),
                output_schemas=("TopologyArtifact",),
                required_credentials=(),
                config_schema={},
            )
            registry.register(m)
            renderer = DocumentationHyperFrameRenderer()
            seq = renderer.render_connector_catalog(registry)
            assert seq.total_frames >= 2  # overview + at least 1 connector + trust tiers
            assert any("Test" in (f.frame_metadata.get("title", "")) for f in seq.frames)
        finally:
            os.unlink(path)

    def test_render_test_dashboard(self):
        renderer = DocumentationHyperFrameRenderer()
        modules = [
            {"name": "core", "total": 100, "passed": 100, "failed": 0, "skipped": 0, "duration": 1.2},
            {"name": "event", "total": 66, "passed": 66, "failed": 0, "skipped": 0, "duration": 0.8},
        ]
        seq = renderer.render_test_dashboard("Full Suite", passed=166, failed=0, skipped=0, modules=modules)
        assert seq.total_frames == 4  # summary + 2 modules + status
        assert seq.frames[-1].frame_metadata.get("title") == "Suite Status"

    def test_documentation_mp4_encoding_exists(self):
        # We don't encode actual MP4 in tests (requires imageio), but we verify
        # the method exists and has the right signature
        renderer = DocumentationHyperFrameRenderer()
        assert hasattr(renderer, "encode_mp4")


# ──────────────────────────────
#  Infrastructure Replay Video Tests
# ──────────────────────────────


class TestInfrastructureReplayHyperFrames:
    def test_render_connector_ingestion(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        receipts = [
            IngestionReceipt(
                receipt_id="r1",
                connector_id="c.k8s",
                connector_version="1.0.0",
                tenant_id="t1",
                actor_id="u1",
                correlation_id="run1",
                ingestion_start="2026-01-01T00:00:00Z",
                ingestion_end="2026-01-01T00:00:01Z",
                artifact_count=2,
                artifact_hashes=("h1", "h2"),
                fence_used=ConnectorExecutionFence.SANDBOXED_READ,
                sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
                error_count=0,
                errors=(),
            ),
            IngestionReceipt(
                receipt_id="r2",
                connector_id="c.tf",
                connector_version="1.0.0",
                tenant_id="t1",
                actor_id="u1",
                correlation_id="run1",
                ingestion_start="2026-01-01T00:00:02Z",
                ingestion_end="2026-01-01T00:00:03Z",
                artifact_count=1,
                artifact_hashes=("h3",),
                fence_used=ConnectorExecutionFence.SANDBOXED_READ,
                sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
                error_count=0,
                errors=(),
            ),
        ]
        seq = renderer.render_connector_ingestion(receipts)
        assert seq.total_frames == 4  # overview + 2 receipts + summary
        assert seq.sequence_hash != ""
        assert all(f.frame_hash != "" for f in seq.frames)

    def test_render_topology_construction(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        dt = DigitalTwinImport("t1")
        for i in range(3):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "pod"}],
                edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 3}", "relation": "link"}],
                source_system="k8s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            dt.import_artifact(a)
        seq = renderer.render_topology_construction(dt)
        assert seq.total_frames == 5  # empty + 3 artifacts + final
        assert seq.frames[-1].frame_metadata.get("title") == "Final Topology"

    def test_render_drift_evolution(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        snapshots = [
            {
                "graph_hash": "abc",
                "node_count": 2,
                "edge_count": 1,
                "stable": True,
                "added_nodes": [],
                "removed_nodes": [],
            },
            {
                "graph_hash": "def",
                "node_count": 3,
                "edge_count": 2,
                "stable": False,
                "added_nodes": ["n3"],
                "removed_nodes": [],
            },
            {
                "graph_hash": "ghi",
                "node_count": 3,
                "edge_count": 2,
                "stable": True,
                "added_nodes": [],
                "removed_nodes": [],
            },
        ]
        seq = renderer.render_drift_evolution(snapshots)
        assert seq.total_frames == 4  # baseline + 2 snapshots + assessment
        # Frame 2 (snapshot 1) should have lines with drift status
        assert seq.frames[2].frame_metadata.get("line_count", 0) > 0

    def test_render_drift_empty(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        seq = renderer.render_drift_evolution([])
        assert seq.total_frames == 1
        assert seq.frames[0].frame_metadata.get("title") == "Empty"

    def test_render_blast_radius(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        graph = UnifiedTopologyGraph("t1", "c1")
        for i in range(5):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 5}", "relation": "link"}],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            graph.add_artifact(a)
        risk = RiskPropagationTopology(graph)
        seq = renderer.render_blast_radius_propagation(risk, "n0", max_hops=3)
        assert seq.total_frames == 5  # origin + 3 hops + complete
        assert seq.frames[-1].frame_metadata.get("title") == "Blast Radius: Complete"

    def test_render_governance_audit_trail(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        decisions = [
            GovernanceDecision(
                decision_id="d1",
                context_id="c1",
                effect=Effect.ALLOW,
                matched_rules=["rule_a"],
                denied_by="",
                evaluated_at="2026-01-01T00:00:00Z",
            ),
            GovernanceDecision(
                decision_id="d2",
                context_id="c2",
                effect=Effect.DENY,
                matched_rules=[],
                denied_by="governance:unknown_connector",
                evaluated_at="2026-01-01T00:00:01Z",
            ),
        ]
        seq = renderer.render_governance_audit_trail(decisions)
        assert seq.total_frames == 4  # overview + 2 decisions + summary
        assert any(d.effect.value == "allow" for d in decisions)

    def test_infrastructure_mp4_encoding_exists(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        assert hasattr(renderer, "encode_mp4")

    def test_deterministic_frame_hashes(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        receipts = [
            IngestionReceipt(
                receipt_id="r1",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                actor_id="u1",
                correlation_id="c1",
                ingestion_start="2026-01-01T00:00:00Z",
                ingestion_end="2026-01-01T00:00:01Z",
                artifact_count=1,
                artifact_hashes=("h1",),
                fence_used=ConnectorExecutionFence.SANDBOXED_READ,
                sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
                error_count=0,
                errors=(),
            ),
        ]
        seq1 = renderer.render_connector_ingestion(receipts)
        seq2 = renderer.render_connector_ingestion(receipts)
        assert seq1.sequence_hash == seq2.sequence_hash
        for f1, f2 in zip(seq1.frames, seq2.frames):
            assert f1.frame_hash == f2.frame_hash

    def test_all_frames_have_hashes(self):
        renderer = InfrastructureReplayHyperFrameRenderer()
        dt = DigitalTwinImport("t1")
        a = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a)
        seq = renderer.render_topology_construction(dt)
        for frame in seq.frames:
            assert frame.frame_hash != ""
            assert len(frame.frame_hash) == 64


# ──────────────────────────────
#  Integration
# ──────────────────────────────


class TestHyperFramesVideoIntegration:
    def test_documentation_and_infrastructure_sequences_different(self):
        doc_renderer = DocumentationHyperFrameRenderer()
        infra_renderer = InfrastructureReplayHyperFrameRenderer()

        doc_seq = doc_renderer.render_governance_invariants(
            [{"id": "INV1", "description": "Test", "enforcement": "static", "scope": "global"}]
        )

        dt = DigitalTwinImport("t1")
        a = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a)
        infra_seq = infra_renderer.render_topology_construction(dt)

        assert doc_seq.sequence_hash != infra_seq.sequence_hash

    def test_frame_metadata_populated(self):
        renderer = DocumentationHyperFrameRenderer()
        seq = renderer.render_test_dashboard("X", passed=1, failed=0, skipped=0, modules=[])
        for frame in seq.frames:
            assert "title" in frame.frame_metadata
            assert "line_count" in frame.frame_metadata
