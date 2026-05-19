"""Digital Twin Conformance Tests.

50+ tests covering Snapshot, Diff, Propagation, Replay, and HyperFrames.
All tests verify deterministic behavior, immutability, tenant isolation,
and the no-mutation replay boundary.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

import pytest

from pi_interoperability_layer.snapshot.artifacts import (
    HashChainBreakError,
    RetentionPolicy,
    SnapshotArtifact,
    SnapshotChain,
    SnapshotPayload,
    SnapshotType,
)
from pi_interoperability_layer.snapshot.clock import (
    ClockSkewViolation,
    DeterministicClock,
    TimestampMarker,
    canonical_timestamp,
    compare_timestamps,
)
from pi_interoperability_layer.snapshot.registry import (
    ClockOrderViolation,
    SnapshotRegistry,
)
from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.receipts import OrchestrationLedger
from pi_interoperability_layer.blast_radius import TopologyGraph, TopologyNode, TopologyEdge
from pi_interoperability_layer.drift_propagation import (
    DriftPropagationEngine,
    RiskPropagationGraph,
)
from pi_interoperability_layer.temporal_replay import (
    ReplayCheckpoint,
    ReplayTimeline,
    TemporalReplayEngine,
)
from pi_interoperability_layer.hyperframes import (
    HyperFrameRenderEngine,
    RenderConfig,
)
from pi_interoperability_layer.workers.pi_observability_diff_worker import (
    DeltaType,
    PiObservabilityDiffWorker,
    SemanticDelta,
    SemanticDiffEngine,
    SemanticDriftReport,
)


# ──────────────────────────────
#  Snapshot Artifact Tests
# ──────────────────────────────

class TestSnapshotArtifact:
    def _make_artifact(
        self,
        snap_id: str = "snap_001",
        tenant: str = "t1",
        source: str = "src_a",
        stype: SnapshotType = SnapshotType.CONFIGURATION,
        data: Dict[str, Any] = None,
        prev_hash: str = "",
    ) -> SnapshotArtifact:
        payload = SnapshotPayload(
            snapshot_type=stype,
            tenant_id=tenant,
            source_id=source,
            data=data or {"key": "value"},
        )
        marker = TimestampMarker(
            wall_time=datetime.now(timezone.utc),
            sequence_number=1,
            clock_id="test_clock",
        )
        return SnapshotArtifact(
            snapshot_id=snap_id,
            base_snapshot_id=None,
            timestamp_marker=marker,
            payload=payload,
            previous_snapshot_hash=prev_hash,
        )

    def test_payload_hash_is_deterministic(self) -> None:
        a = self._make_artifact(data={"b": 2, "a": 1})
        b = self._make_artifact(data={"a": 1, "b": 2})
        assert a.payload_hash == b.payload_hash

    def test_artifact_hash_includes_previous_snapshot_hash(self) -> None:
        a = self._make_artifact(prev_hash="")
        b = self._make_artifact(prev_hash="abc123")
        assert a.artifact_hash != b.artifact_hash

    def test_snapshot_is_frozen_no_mutation(self) -> None:
        a = self._make_artifact()
        with pytest.raises(Exception):
            a.snapshot_id = "tampered"

    def test_snapshot_chain_continuity(self) -> None:
        a = self._make_artifact(snap_id="snap_1", prev_hash="")
        chain = SnapshotChain(
            chain_id="c1",
            tenant_id="t1",
            source_id="src_a",
            snapshot_type=SnapshotType.CONFIGURATION,
        )
        chain.append(a)
        b = self._make_artifact(snap_id="snap_2", prev_hash=a.artifact_hash)
        chain.append(b)
        assert chain.head_snapshot_id == "snap_2"
        assert chain.head_snapshot_hash == b.artifact_hash

    def test_snapshot_chain_break_detected(self) -> None:
        a = self._make_artifact(snap_id="snap_1", prev_hash="")
        chain = SnapshotChain(
            chain_id="c1",
            tenant_id="t1",
            source_id="src_a",
            snapshot_type=SnapshotType.CONFIGURATION,
        )
        chain.append(a)
        b = self._make_artifact(snap_id="snap_2", prev_hash="wrong_hash")
        with pytest.raises(HashChainBreakError):
            chain.append(b)

    def test_retention_policy_classification(self) -> None:
        policy = RetentionPolicy(
            policy_id="test",
            hot_ttl_days=7,
            warm_ttl_days=30,
            cold_ttl_days=90,
            archive_ttl_days=365,
        )
        assert policy.classify_age(3.0) == "hot"
        assert policy.classify_age(15.0) == "warm"
        assert policy.classify_age(60.0) == "cold"
        assert policy.classify_age(200.0) == "archive"


# ──────────────────────────────
#  SnapshotRegistry Tests
# ──────────────────────────────

class TestSnapshotRegistry:
    def _reg(self) -> SnapshotRegistry:
        return SnapshotRegistry(registry_id="reg_test")

    def _artifact(
        self,
        snap_id: str,
        tenant: str = "t1",
        source: str = "src_a",
        stype: SnapshotType = SnapshotType.CONFIGURATION,
        data: Dict[str, Any] = None,
        prev_hash: str = "",
        seq: int = 1,
    ) -> SnapshotArtifact:
        payload = SnapshotPayload(
            snapshot_type=stype,
            tenant_id=tenant,
            source_id=source,
            data=data or {"key": snap_id},
        )
        marker = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seq),
            sequence_number=seq,
            clock_id="test",
        )
        return SnapshotArtifact(
            snapshot_id=snap_id,
            timestamp_marker=marker,
            payload=payload,
            previous_snapshot_hash=prev_hash,
        )

    def test_store_and_retrieve(self) -> None:
        reg = self._reg()
        a = self._artifact("snap_1", prev_hash="")
        reg.store(a)
        got = reg.get("snap_1")
        assert got is not None
        assert got.snapshot_id == "snap_1"

    def test_tenant_isolation(self) -> None:
        reg = self._reg()
        a = self._artifact("snap_a", tenant="t1")
        b = self._artifact("snap_b", tenant="t2")
        reg.store(a)
        reg.store(b)
        t1_snaps = reg.list_snapshots(tenant_id="t1")
        assert all(s.tenant_id == "t1" for s in t1_snaps)
        assert len(t1_snaps) == 1

    def test_list_snapshots_ordered(self) -> None:
        reg = self._reg()
        a = self._artifact("snap_1", seq=1, prev_hash="")
        b = self._artifact("snap_2", seq=2, prev_hash=a.artifact_hash)
        reg.store(a)
        reg.store(b)
        snaps = reg.list_snapshots(tenant_id="t1")
        assert snaps[0].snapshot_id == "snap_1"
        assert snaps[1].snapshot_id == "snap_2"

    def test_latest_retrieval(self) -> None:
        reg = self._reg()
        a = self._artifact("snap_1", seq=1, prev_hash="")
        b = self._artifact("snap_2", seq=2, prev_hash=a.artifact_hash)
        reg.store(a)
        reg.store(b)
        latest = reg.latest("t1", "src_a", SnapshotType.CONFIGURATION)
        assert latest.snapshot_id == "snap_2"

    def test_integrity_verification_passes(self) -> None:
        reg = self._reg()
        a = self._artifact("snap_1", prev_hash="")
        reg.store(a)
        ok, errs = reg.verify_integrity()
        assert ok is True
        assert errs == []

    def test_clock_order_violation_rejected(self) -> None:
        reg = self._reg()
        # Create artifact with seq=2 first
        a = self._artifact("snap_later", seq=2, prev_hash="")
        reg.store(a)
        # Now try to store one with seq=1 (earlier timestamp)
        b = self._artifact("snap_earlier", seq=1, prev_hash="")
        with pytest.raises(ClockOrderViolation):
            reg.store(b)


# ──────────────────────────────
#  DeterministicClock Tests
# ──────────────────────────────

class TestDeterministicClock:
    def test_canonical_timestamp_format(self) -> None:
        dt = datetime(2026, 5, 19, 12, 30, 45, 123456, tzinfo=timezone.utc)
        s = canonical_timestamp(dt)
        assert s.endswith("Z")
        assert "+00:00" not in s

    def test_timestamp_comparison(self) -> None:
        a = datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc)
        b = datetime(2026, 5, 19, 12, 0, 1, tzinfo=timezone.utc)
        assert compare_timestamps(a, b) == -1
        assert compare_timestamps(b, a) == 1
        assert compare_timestamps(a, a) == 0

    def test_timestamp_marker_ordering(self) -> None:
        m1 = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            sequence_number=1,
            clock_id="c1",
        )
        m2 = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            sequence_number=2,
            clock_id="c1",
        )
        assert m1 < m2
        assert m2 > m1

    def test_clock_produces_hash(self) -> None:
        clock = DeterministicClock(clock_id="test")
        dt = clock.now()
        h = clock.hash_timestamp(dt)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ──────────────────────────────
#  SemanticDiffEngine Tests
# ──────────────────────────────

class TestSemanticDiffEngine:
    def _snapshot(
        self,
        snap_id: str,
        tenant: str = "t1",
        stype: SnapshotType = SnapshotType.CONFIGURATION,
        data: Dict[str, Any] = None,
    ) -> SnapshotArtifact:
        payload = SnapshotPayload(
            snapshot_type=stype,
            tenant_id=tenant,
            source_id="src_a",
            data=data or {},
        )
        marker = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            sequence_number=1,
            clock_id="test",
        )
        return SnapshotArtifact(
            snapshot_id=snap_id,
            timestamp_marker=marker,
            payload=payload,
            previous_snapshot_hash="",
        )

    def test_config_added_detected(self) -> None:
        base = self._snapshot("base", data={"config": {"a": 1}})
        mod = self._snapshot("mod", data={"config": {"a": 1, "b": 2}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("config_added", 0) == 1
        assert any(d.delta_type == DeltaType.CONFIG_ADDED for d in report.deltas)

    def test_config_removed_detected(self) -> None:
        base = self._snapshot("base", data={"config": {"a": 1, "b": 2}})
        mod = self._snapshot("mod", data={"config": {"a": 1}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("config_removed", 0) == 1

    def test_config_changed_detected(self) -> None:
        base = self._snapshot("base", data={"config": {"a": 1}})
        mod = self._snapshot("mod", data={"config": {"a": 2}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("config_changed", 0) == 1

    def test_state_increased_directional(self) -> None:
        base = self._snapshot("base", stype=SnapshotType.STATE, data={"state": {"cpu": 40}})
        mod = self._snapshot("mod", stype=SnapshotType.STATE, data={"state": {"cpu": 60}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("state_increased", 0) == 1

    def test_state_decreased_directional(self) -> None:
        base = self._snapshot("base", stype=SnapshotType.STATE, data={"state": {"cpu": 60}})
        mod = self._snapshot("mod", stype=SnapshotType.STATE, data={"state": {"cpu": 40}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("state_decreased", 0) == 1

    def test_capability_added_removed(self) -> None:
        base = self._snapshot("base", stype=SnapshotType.CAPABILITY_MESH, data={"capabilities": ["cap_a"]})
        mod = self._snapshot("mod", stype=SnapshotType.CAPABILITY_MESH, data={"capabilities": ["cap_a", "cap_b"]})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert report.delta_counts.get("capability_added", 0) == 1

    def test_drift_scores_bounded(self) -> None:
        base = self._snapshot("base", data={"config": {"a": 1}})
        mod = self._snapshot("mod", data={"config": {"a": 2, "b": 3, "c": 4}})
        engine = SemanticDiffEngine()
        report = engine.diff(base, mod)
        assert 0.0 <= report.total_drift_score <= 1.0
        assert 0.0 <= report.structural_drift <= 1.0
        assert 0.0 <= report.semantic_drift <= 1.0

    def test_report_hash_is_deterministic(self) -> None:
        base = self._snapshot("base", data={"config": {"a": 1}})
        mod = self._snapshot("mod", data={"config": {"a": 2}})
        engine = SemanticDiffEngine()
        r1 = engine.diff(base, mod)
        r2 = engine.diff(base, mod)
        assert r1.report_hash == r2.report_hash
        assert r1.input_hash == r2.input_hash

    def test_cross_tenant_rejected(self) -> None:
        base = self._snapshot("base", tenant="t1")
        mod = self._snapshot("mod", tenant="t2")
        engine = SemanticDiffEngine()
        with pytest.raises(ValueError):
            engine.diff(base, mod)

    def test_cross_type_rejected(self) -> None:
        base = self._snapshot("base", stype=SnapshotType.CONFIGURATION)
        mod = self._snapshot("mod", stype=SnapshotType.STATE)
        engine = SemanticDiffEngine()
        with pytest.raises(ValueError):
            engine.diff(base, mod)


# ──────────────────────────────
#  PiObservabilityDiffWorker Tests
# ──────────────────────────────

class TestPiObservabilityDiffWorker:
    def test_worker_contract_deterministic(self) -> None:
        bus = ArtifactBus()
        ledger = OrchestrationLedger()
        worker = PiObservabilityDiffWorker("test_worker", bus, ledger)
        assert worker.contract.deterministic is True
        assert worker.contract.worker_class == "PiObservabilityDiffWorker"

    def test_worker_execution_produces_receipt(self) -> None:
        bus = ArtifactBus()
        ledger = OrchestrationLedger()
        worker = PiObservabilityDiffWorker("test_worker", bus, ledger)

        payload = SnapshotPayload(
            snapshot_type=SnapshotType.CONFIGURATION,
            tenant_id="t1",
            source_id="src_a",
            data={"config": {"a": 1}},
        )
        marker = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            sequence_number=1,
            clock_id="test",
        )
        base = SnapshotArtifact(
            snapshot_id="base",
            timestamp_marker=marker,
            payload=payload,
            previous_snapshot_hash="",
        )
        mod = SnapshotArtifact(
            snapshot_id="mod",
            timestamp_marker=marker,
            payload=payload.model_copy(update={"data": {"config": {"a": 2}}}),
            previous_snapshot_hash="",
        )

        slot_base = bus.write(ArtifactSlot(
            producer_worker_id="input",
            artifact_type="SnapshotArtifact",
            payload=base.model_dump(mode="json"),
        ))
        slot_mod = bus.write(ArtifactSlot(
            producer_worker_id="input",
            artifact_type="SnapshotArtifact",
            payload=mod.model_dump(mode="json"),
        ))

        receipt = worker.execute(phase="DIFF", input_slot_ids=[slot_base.slot_id, slot_mod.slot_id])
        assert receipt.status == "SUCCESS"
        assert receipt.determinism_proof != ""
        assert len(receipt.output_slot_ids) == 1

    def test_worker_rejects_mismatched_input_count(self) -> None:
        bus = ArtifactBus()
        ledger = OrchestrationLedger()
        worker = PiObservabilityDiffWorker("test_worker", bus, ledger)
        receipt = worker.execute(phase="DIFF", input_slot_ids=["only_one"])
        assert receipt.status == "SCHEMA_MISMATCH"


# ──────────────────────────────
#  DriftPropagationEngine Tests
# ──────────────────────────────

class TestDriftPropagationEngine:
    def _topology(self) -> TopologyGraph:
        return TopologyGraph(
            graph_id="topo_1",
            nodes={
                "svc_a": TopologyNode(node_id="svc_a", node_type="service", dependencies=["svc_b"]),
                "svc_b": TopologyNode(node_id="svc_b", node_type="service", dependencies=["svc_c"]),
                "svc_c": TopologyNode(node_id="svc_c", node_type="database"),
            },
            edges=[
                TopologyEdge(edge_id="e1", upstream="svc_a", downstream="svc_b", carries_auth=True),
                TopologyEdge(edge_id="e2", upstream="svc_b", downstream="svc_c", carries_state=True),
            ],
        )

    def _drift_report(self, deltas: List[SemanticDelta]) -> SemanticDriftReport:
        return SemanticDriftReport(
            report_id="drift_1",
            baseline_snapshot_id="base",
            modified_snapshot_id="mod",
            deltas=deltas,
        )

    def test_direct_blast_radius_marked(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        engine = DriftPropagationEngine(max_propagation_depth=2)
        risk = engine.simulate(topo, report)
        node_a = risk.nodes["svc_a"]
        assert node_a.in_direct_blast_radius is True
        assert node_a.risk_level == "HIGH"

    def test_propagation_reaches_downstream(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        engine = DriftPropagationEngine(max_propagation_depth=2)
        risk = engine.simulate(topo, report)
        assert risk.nodes["svc_b"].risk_level != "NONE"
        assert risk.nodes["svc_c"].risk_level != "NONE"

    def test_propagation_bounded_by_depth(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        engine = DriftPropagationEngine(max_propagation_depth=0)
        risk = engine.simulate(topo, report)
        assert risk.nodes["svc_b"].risk_level == "NONE"
        assert risk.nodes["svc_c"].risk_level == "NONE"

    def test_auth_edge_amplifies_propagation(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        # With auth_multiplier=2, svc_b should receive amplified risk
        engine = DriftPropagationEngine(max_propagation_depth=1, auth_propagation_multiplier=2)
        risk = engine.simulate(topo, report)
        # svc_b is reached at depth 1, but with amplification it should still be HIGH
        assert risk.nodes["svc_b"].risk_level == "HIGH"

    def test_aggregate_metrics_present(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        engine = DriftPropagationEngine()
        risk = engine.simulate(topo, report)
        assert risk.total_nodes_at_risk >= 1
        assert risk.max_propagation_depth >= 0
        assert len(risk.graph_hash) == 64

    def test_graph_hash_deterministic(self) -> None:
        topo = self._topology()
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.NODE_ADDED,
                path="nodes.svc_a",
                description="Added svc_a",
                severity="HIGH",
            ),
        ]
        report = self._drift_report(deltas)
        engine = DriftPropagationEngine()
        r1 = engine.simulate(topo, report)
        r2 = engine.simulate(topo, report)
        assert r1.graph_hash == r2.graph_hash


# ──────────────────────────────
#  TemporalReplayEngine Tests
# ──────────────────────────────

class TestTemporalReplayEngine:
    def _reg_with_snapshots(self) -> SnapshotRegistry:
        reg = SnapshotRegistry(registry_id="reg_replay")
        for i, snap_id in enumerate(["snap_1", "snap_2", "snap_3"]):
            payload = SnapshotPayload(
                snapshot_type=SnapshotType.CONFIGURATION,
                tenant_id="t1",
                source_id="src_a",
                data={"version": i + 1},
            )
            marker = TimestampMarker(
                wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc) + timedelta(hours=i),
                sequence_number=i + 1,
                clock_id="replay_test",
            )
            prev = ""
            if i > 0:
                prev = reg._artifacts[f"snap_{i}"].artifact_hash
            artifact = SnapshotArtifact(
                snapshot_id=snap_id,
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash=prev,
            )
            reg.store(artifact)
        return reg

    def test_reconstruct_state_at_returns_nearest(self) -> None:
        reg = self._reg_with_snapshots()
        engine = TemporalReplayEngine(reg)
        target = datetime(2026, 5, 19, 13, 30, 0, tzinfo=timezone.utc)
        cp = engine.reconstruct_state_at("t1", "src_a", SnapshotType.CONFIGURATION, target)
        assert cp is not None
        assert cp.reconstructed_snapshot.snapshot_id == "snap_2"
        assert cp.read_only is True

    def test_reconstruct_state_at_returns_none_if_no_snapshot(self) -> None:
        reg = self._reg_with_snapshots()
        engine = TemporalReplayEngine(reg)
        target = datetime(2026, 5, 19, 10, 0, 0, tzinfo=timezone.utc)
        cp = engine.reconstruct_state_at("t1", "src_a", SnapshotType.CONFIGURATION, target)
        assert cp is None

    def test_build_timeline_ordered(self) -> None:
        reg = self._reg_with_snapshots()
        engine = TemporalReplayEngine(reg)
        timeline = engine.build_timeline("t1", "src_a", SnapshotType.CONFIGURATION)
        assert len(timeline.checkpoints) == 3
        for i in range(1, len(timeline.checkpoints)):
            assert timeline.checkpoints[i].target_timestamp >= timeline.checkpoints[i - 1].target_timestamp

    def test_checkpoint_hash_deterministic(self) -> None:
        reg = self._reg_with_snapshots()
        engine = TemporalReplayEngine(reg)
        target = datetime(2026, 5, 19, 13, 30, 0, tzinfo=timezone.utc)
        cp1 = engine.reconstruct_state_at("t1", "src_a", SnapshotType.CONFIGURATION, target)
        cp2 = engine.reconstruct_state_at("t1", "src_a", SnapshotType.CONFIGURATION, target)
        assert cp1.checkpoint_hash == cp2.checkpoint_hash

    def test_engine_does_not_mutate_registry(self) -> None:
        reg = self._reg_with_snapshots()
        count_before = reg.snapshot_count()
        engine = TemporalReplayEngine(reg)
        _ = engine.build_timeline("t1", "src_a", SnapshotType.CONFIGURATION)
        count_after = reg.snapshot_count()
        assert count_after == count_before

    def test_diff_at_points_returns_read_only(self) -> None:
        reg = self._reg_with_snapshots()
        engine = TemporalReplayEngine(reg)
        t_a = datetime(2026, 5, 19, 12, 30, 0, tzinfo=timezone.utc)
        t_b = datetime(2026, 5, 19, 14, 30, 0, tzinfo=timezone.utc)
        cp_a, cp_b = engine.diff_at_points("t1", "src_a", SnapshotType.CONFIGURATION, t_a, t_b)
        assert cp_a is not None
        assert cp_b is not None
        assert cp_a.read_only is True
        assert cp_b.read_only is True


# ──────────────────────────────
#  HyperFrameRenderEngine Tests
# ──────────────────────────────

class TestHyperFrameRenderEngine:
    def _drift_report(self) -> SemanticDriftReport:
        deltas = [
            SemanticDelta(
                delta_id="d1",
                delta_type=DeltaType.CONFIG_ADDED,
                path="config.region",
                description="Region added",
                severity="MEDIUM",
            ),
            SemanticDelta(
                delta_id="d2",
                delta_type=DeltaType.STATE_CHANGED,
                path="state.cpu",
                description="CPU changed",
                severity="LOW",
            ),
        ]
        return SemanticDriftReport(
            report_id="drift_test",
            baseline_snapshot_id="base",
            modified_snapshot_id="mod",
            deltas=deltas,
        )

    def test_render_drift_report_produces_sequence(self) -> None:
        engine = HyperFrameRenderEngine()
        report = self._drift_report()
        seq = engine.render_drift_report(report)
        assert len(seq.frames) > 0
        assert seq.sequence_id == f"hyper_{report.report_id}"
        assert seq.source_report_id == report.report_id

    def test_frame_sequence_hash_deterministic(self) -> None:
        engine = HyperFrameRenderEngine()
        report = self._drift_report()
        s1 = engine.render_drift_report(report)
        s2 = engine.render_drift_report(report)
        assert s1.sequence_hash == s2.sequence_hash

    def test_render_risk_graph_produces_sequence(self) -> None:
        engine = HyperFrameRenderEngine()
        topo = TopologyGraph(
            graph_id="topo_test",
            nodes={"svc_a": TopologyNode(node_id="svc_a", node_type="service")},
            edges=[],
        )
        report = self._drift_report()
        dpe = DriftPropagationEngine()
        risk = dpe.simulate(topo, report)
        seq = engine.render_risk_graph(risk)
        assert len(seq.frames) == 5  # overview, direct, depth, full, aggregate
        assert seq.source_report_id == report.report_id

    def test_render_config_affects_output(self) -> None:
        report = self._drift_report()
        cfg1 = RenderConfig(config_id="c1", width=640, height=480, fps=1)
        cfg2 = RenderConfig(config_id="c2", width=1280, height=720, fps=2)
        e1 = HyperFrameRenderEngine(cfg1)
        e2 = HyperFrameRenderEngine(cfg2)
        s1 = e1.render_drift_report(report)
        s2 = e2.render_drift_report(report)
        assert s1.width == 640
        assert s2.width == 1280
        assert s1.fps == 1
        assert s2.fps == 2

    def test_frame_data_is_base64_png(self) -> None:
        engine = HyperFrameRenderEngine()
        report = self._drift_report()
        seq = engine.render_drift_report(report)
        for frame in seq.frames:
            assert frame.frame_data != ""
            # Verify base64 decodes
            raw = base64.b64decode(frame.frame_data)
            assert raw[:8] == b"\x89PNG\r\n\x1a\n"


# ──────────────────────────────
#  Integration Tests
# ──────────────────────────────

class TestDigitalTwinIntegration:
    def test_end_to_end_pipeline(self) -> None:
        # Phase 1: Store snapshots
        reg = SnapshotRegistry(registry_id="reg_integ")
        base_data = {"config": {"region": "us-east-1", "replicas": 2}, "state": {"cpu": 40}}
        mod_data = {"config": {"region": "us-east-1", "replicas": 3, "cache": "enabled"}, "state": {"cpu": 65}}

        for i, (snap_id, data) in enumerate([("base", base_data), ("mod", mod_data)]):
            payload = SnapshotPayload(
                snapshot_type=SnapshotType.CONFIGURATION,
                tenant_id="t1",
                source_id="k8s_prod",
                data=data,
            )
            marker = TimestampMarker(
                wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc) + timedelta(hours=i),
                sequence_number=i + 1,
                clock_id="integ",
            )
            prev = ""
            if i > 0:
                prev = reg._artifacts["base"].artifact_hash
            artifact = SnapshotArtifact(
                snapshot_id=snap_id,
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash=prev,
            )
            reg.store(artifact)

        # Phase 2: Diff
        base_snap = reg.get("base")
        mod_snap = reg.get("mod")
        diff_engine = SemanticDiffEngine()
        report = diff_engine.diff(base_snap, mod_snap)
        assert report.total_drift_score > 0

        # Phase 3: Risk propagation
        topo = TopologyGraph(
            graph_id="topo_integ",
            nodes={
                "svc_a": TopologyNode(node_id="svc_a", node_type="service", dependencies=["svc_b"]),
                "svc_b": TopologyNode(node_id="svc_b", node_type="service"),
            },
            edges=[
                TopologyEdge(edge_id="e1", upstream="svc_a", downstream="svc_b", carries_auth=True),
            ],
        )
        dpe = DriftPropagationEngine()
        risk = dpe.simulate(topo, report)
        assert risk.total_nodes_at_risk >= 0

        # Phase 4: Replay
        replay_engine = TemporalReplayEngine(reg)
        cp = replay_engine.reconstruct_state_at("t1", "k8s_prod", SnapshotType.CONFIGURATION, datetime(2026, 5, 19, 12, 30, 0, tzinfo=timezone.utc))
        assert cp is not None
        assert cp.read_only is True

        # Phase 5: HyperFrames
        hf_engine = HyperFrameRenderEngine()
        seq = hf_engine.render_drift_report(report)
        assert len(seq.frames) > 0
        assert seq.sequence_hash != ""

    def test_tenant_isolation_across_pipeline(self) -> None:
        reg = SnapshotRegistry(registry_id="reg_iso")
        for tenant in ["t1", "t2"]:
            payload = SnapshotPayload(
                snapshot_type=SnapshotType.CONFIGURATION,
                tenant_id=tenant,
                source_id="src",
                data={"key": tenant},
            )
            marker = TimestampMarker(
                wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
                sequence_number=1,
                clock_id="iso",
            )
            reg.store(SnapshotArtifact(
                snapshot_id=f"snap_{tenant}",
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash="",
            ))

        base = reg.get("snap_t1")
        mod = reg.get("snap_t2")
        diff_engine = SemanticDiffEngine()
        with pytest.raises(ValueError):
            diff_engine.diff(base, mod)

    def test_determinism_proof_pipeline(self) -> None:
        reg = SnapshotRegistry(registry_id="reg_det")
        data = {"config": {"a": 1}}
        for i, snap_id in enumerate(["s1", "s2"]):
            payload = SnapshotPayload(
                snapshot_type=SnapshotType.CONFIGURATION,
                tenant_id="t1",
                source_id="src",
                data=data if i == 0 else {"config": {"a": 2}},
            )
            marker = TimestampMarker(
                wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc) + timedelta(hours=i),
                sequence_number=i + 1,
                clock_id="det",
            )
            prev = "" if i == 0 else reg._artifacts["s1"].artifact_hash
            reg.store(SnapshotArtifact(
                snapshot_id=snap_id,
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash=prev,
            ))

        base = reg.get("s1")
        mod = reg.get("s2")
        diff_engine = SemanticDiffEngine()
        r1 = diff_engine.diff(base, mod)
        r2 = diff_engine.diff(base, mod)
        assert r1.report_hash == r2.report_hash
        assert r1.total_drift_score == r2.total_drift_score
        assert r1.structural_drift == r2.structural_drift
        assert r1.semantic_drift == r2.semantic_drift

    def test_no_mutation_boundary_enforced(self) -> None:
        reg = SnapshotRegistry(registry_id="reg_boundary")
        payload = SnapshotPayload(
            snapshot_type=SnapshotType.CONFIGURATION,
            tenant_id="t1",
            source_id="src",
            data={"a": 1},
        )
        marker = TimestampMarker(
            wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            sequence_number=1,
            clock_id="boundary",
        )
        reg.store(SnapshotArtifact(
            snapshot_id="snap",
            timestamp_marker=marker,
            payload=payload,
            previous_snapshot_hash="",
        ))

        engine = TemporalReplayEngine(reg)
        timeline = engine.build_timeline("t1", "src", SnapshotType.CONFIGURATION)
        for cp in timeline.checkpoints:
            assert cp.read_only is True
            # Verify checkpoint is frozen
            with pytest.raises(Exception):
                cp.read_only = False

    def test_snapshot_registry_integrity(self) -> None:
        reg = SnapshotRegistry(registry_id="reg_integ_check")
        for i in range(3):
            payload = SnapshotPayload(
                snapshot_type=SnapshotType.STATE,
                tenant_id="t1",
                source_id="src",
                data={"cpu": 10 * (i + 1)},
            )
            marker = TimestampMarker(
                wall_time=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=i),
                sequence_number=i + 1,
                clock_id="integ",
            )
            prev = ""
            if i > 0:
                prev = reg._artifacts[f"snap_{i}"].artifact_hash
            reg.store(SnapshotArtifact(
                snapshot_id=f"snap_{i + 1}",
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash=prev,
            ))
        ok, errs = reg.verify_integrity()
        assert ok is True
        assert errs == []
