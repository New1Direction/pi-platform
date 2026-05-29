"""Reproducibility regression tests for pi_interoperability_layer.

The platform brands itself a "deterministic kernel": its SHA-256 identity
hashes are sold as reproducibility proof. These tests pin that contract by
building the SAME logical object twice (two fresh instances) and asserting the
identity hash is IDENTICAL across instances — proving no wall-clock
(datetime.now/utcnow/time.time) or random uuid4 value leaked into the hashed
input. Each test also asserts the wall-clock / id metadata is still RECORDED on
the object (we excluded those fields from the hash, we did not delete them).

Mirrors the reference fix already proven on pi_event_fabric/bus/core.py.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest, TrustZone

from pi_interoperability_layer.capability.registry import (
    RegistryEntry,
    RegistryFingerprints,
    TrustScore,
)
from pi_interoperability_layer.execution import EventRecord
from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, PhaseBoundaryReceipt
from pi_interoperability_layer.platform.execution_fabric import WorkerLease
from pi_interoperability_layer.registry import ReplayBundle
from pi_interoperability_layer.snapshot.artifacts import (
    SnapshotArtifact,
    SnapshotPayload,
    SnapshotType,
)
from pi_interoperability_layer.snapshot.clock import TimestampMarker


class TestReproducibleHashes:
    """Same logical input -> same SHA-256 hash, across fresh instances."""

    def test_event_record_hash_is_reproducible(self) -> None:
        def build() -> EventRecord:
            return EventRecord(
                event_id="evt_1",
                event_type="ARTIFACT_RECEIVED",
                payload={"artifact_id": "a1", "z": 1, "a": 2},
                sequence_number=7,
                previous_hash="prevhash",
                emitted_by="recon",
            )

        e1 = build()
        e2 = build()
        assert e1.compute_hash() == e2.compute_hash()
        assert len(e1.compute_hash()) == 64
        # The wall-clock timestamp is still recorded as metadata.
        assert e1.emitted_at is not None
        # A different logical payload must change the hash.
        e3 = EventRecord(
            event_id="evt_1",
            event_type="ARTIFACT_RECEIVED",
            payload={"artifact_id": "DIFFERENT"},
            sequence_number=7,
            previous_hash="prevhash",
            emitted_by="recon",
        )
        assert e3.compute_hash() != e1.compute_hash()

    def test_execution_receipt_hash_is_reproducible(self) -> None:
        def build() -> ExecutionReceipt:
            return ExecutionReceipt(
                worker_class="EndpointExtractionWorker",
                worker_id="w1",
                phase="EXTRACT",
                input_slot_ids=["s2", "s1"],
                output_slot_ids=["o1"],
                status="SUCCESS",
                determinism_proof="proofhash",
                previous_receipt_hash="prev",
            )

        r1 = build()
        r2 = build()
        # Distinct random receipt_id and distinct wall-clock timestamps...
        assert r1.receipt_id != r2.receipt_id
        # ...but identical content-addressed hashes.
        assert r1.compute_hash() == r2.compute_hash()
        # timestamp + receipt_id metadata are still recorded.
        assert r1.timestamp is not None
        assert r1.receipt_id.startswith("rcpt_")

    def test_phase_boundary_receipt_hash_is_reproducible(self) -> None:
        def build() -> PhaseBoundaryReceipt:
            return PhaseBoundaryReceipt(
                phase="INGEST",
                worker_receipt_ids=["w2", "w1"],
                merged_output_slot_id="merged_1",
                phase_status="SUCCESS",
                previous_boundary_hash="prev",
            )

        b1 = build()
        b2 = build()
        assert b1.boundary_id != b2.boundary_id
        assert b1.compute_hash() == b2.compute_hash()
        assert b1.timestamp is not None
        assert b1.boundary_id.startswith("bnd_")

    def test_snapshot_artifact_hash_is_reproducible(self) -> None:
        payload = SnapshotPayload(
            snapshot_type=SnapshotType.TOPOLOGY,
            tenant_id="t1",
            source_id="src1",
            domain="network",
            data={"nodes": ["n2", "n1"], "edges": []},
        )

        def build(wall: datetime) -> SnapshotArtifact:
            # Same deterministic ordering identity (clock_id + sequence_number)
            # but a DIFFERENT wall_time — the wall-clock must not affect the hash.
            marker = TimestampMarker(
                wall_time=wall,
                sequence_number=3,
                clock_id="clock-A",
            )
            return SnapshotArtifact(
                snapshot_id="snap_1",
                timestamp_marker=marker,
                payload=payload,
                previous_snapshot_hash="prevsnap",
            )

        a1 = build(datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
        a2 = build(datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
        # Different wall-clock markers...
        assert a1.timestamp_marker.ordering_key != a2.timestamp_marker.ordering_key
        # ...but identical content-addressed artifact hashes.
        assert a1.artifact_hash == a2.artifact_hash
        assert a1.payload_hash == a2.payload_hash
        # The wall-clock ordering marker is still recorded as metadata.
        assert a1.timestamp_marker.wall_time is not None

    def test_replay_bundle_hash_is_reproducible(self) -> None:
        # Two bundles with distinct random ids and distinct created_at.
        b1 = ReplayBundle(
            bundle_id="bundle_aaaaaaaaaaaaaaaa",
            baseline_snapshot_id="snap_base",
            modified_snapshot_id="snap_mod",
            diff_report_id="diff_1",
            risk_report_id="risk_1",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        b2 = ReplayBundle(
            bundle_id="bundle_bbbbbbbbbbbbbbbb",
            baseline_snapshot_id="snap_base",
            modified_snapshot_id="snap_mod",
            diff_report_id="diff_1",
            risk_report_id="risk_1",
            created_at=datetime(2099, 6, 6, tzinfo=timezone.utc),
        )
        assert b1.bundle_id != b2.bundle_id
        assert b1.compute_hash() == b2.compute_hash()
        # created_at + bundle_id metadata still recorded.
        assert b1.created_at is not None
        assert b1.bundle_id != ""

    def test_registry_entry_hash_is_reproducible(self) -> None:
        fingerprints = RegistryFingerprints(
            manifest_hash="m",
            source_hash="s",
            determinism_fingerprint="d",
            policy_hash="p",
            normalization_hash="n",
            provenance_chain_hash="c",
        )
        trust = TrustScore(static_clean=50)

        def build(registered_at: str) -> RegistryEntry:
            return RegistryEntry(
                extension_id="ext_1",
                name="ext_1",
                version="1.0.0",
                registered_at=registered_at,
                fingerprints=fingerprints,
                trust_score=trust,
            )

        e1 = build("2026-01-01T00:00:00Z")
        e2 = build("2099-12-31T23:59:59Z")
        # Different registered_at wall-clock values...
        assert e1.registered_at != e2.registered_at
        # ...but identical content-addressed entry hashes.
        assert e1.compute_hash() == e2.compute_hash()
        assert e1.entry_hash == e1.compute_hash()
        # registered_at metadata still recorded.
        assert e1.registered_at != ""

    def test_worker_lease_hash_is_reproducible(self) -> None:
        def build(lease_id: str, worker_id: str, leased_at: str) -> WorkerLease:
            return WorkerLease(
                lease_id=lease_id,
                worker_id=worker_id,
                shard_id="shard-0001",
                phase_number=2,
                manifest_id="m1",
                leased_at=leased_at,
            )

        l1 = build("lease_aaaa", "worker_aaaa", "2026-01-01T00:00:00Z")
        l2 = build("lease_bbbb", "worker_bbbb", "2099-01-01T00:00:00Z")
        # Distinct random ids + distinct wall-clock lease times...
        assert l1.lease_id != l2.lease_id
        assert l1.worker_id != l2.worker_id
        # ...but identical content-addressed lease hashes.
        assert l1.compute_hash() == l2.compute_hash()
        # leased_at + ids still recorded as metadata.
        assert l1.leased_at != ""
        assert l1.lease_id != ""

    def test_two_fresh_instances_match_reference_pattern(self) -> None:
        """End-to-end: a manifest-backed registry entry built in two fully
        independent constructions yields the same hash (the headline claim)."""
        manifest = ExtensionManifest(
            extension_id="ext_repro",
            package_name="ext_repro",
            package_version="2.0.0",
            package_hash="hash_ext_repro",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        fingerprints = RegistryFingerprints(
            manifest_hash=manifest.package_hash,
            source_hash="srchash",
            determinism_fingerprint="detfp",
            policy_hash="polhash",
            normalization_hash="normhash",
            provenance_chain_hash="provhash",
        )
        trust = TrustScore(policy_passed=40, static_clean=30)

        def build() -> RegistryEntry:
            return RegistryEntry(
                extension_id=manifest.extension_id,
                name=manifest.package_name,
                version=manifest.package_version,
                registered_at=datetime.now(timezone.utc).isoformat() + "Z",
                fingerprints=fingerprints,
                trust_score=trust,
            )

        first = build()
        second = build()
        assert first.compute_hash() == second.compute_hash()
