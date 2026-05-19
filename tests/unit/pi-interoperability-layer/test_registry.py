"""Tests for snapshot/replay registry."""

from __future__ import annotations

from pathlib import Path
import tempfile

from pi_interoperability_layer.registry import (
    SnapshotRegistry,
    SnapshotRecord,
    RetentionPolicy,
    ReplayBundle,
)


def test_store_and_load_snapshot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        reg = SnapshotRegistry(Path(tmp))
        payload = {"traces": [{"endpoint_template": "/api/users", "method": "GET"}]}
        record = reg.store_snapshot(runtime="pi-semantic-recon", execution_id="exec_1", payload=payload)
        loaded = reg.load_snapshot(record.metadata.snapshot_id)
        assert loaded is not None
        assert loaded.metadata.runtime == "pi-semantic-recon"
        assert loaded.compute_hash() == record.compute_hash()


def test_store_and_load_bundle() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        reg = SnapshotRegistry(Path(tmp))
        bundle = reg.store_bundle(
            baseline_snapshot_id="snap_base",
            modified_snapshot_id="snap_mod",
            diff_report_id="diff_1",
        )
        loaded = reg.load_bundle(bundle.bundle_id)
        assert loaded is not None
        assert loaded.bundle_hash == bundle.bundle_hash


def test_list_snapshots_by_runtime() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        reg = SnapshotRegistry(Path(tmp))
        reg.store_snapshot("pi-semantic-recon", "exec_1", {"a": 1})
        reg.store_snapshot("pi-semantic-diff", "exec_2", {"b": 2})
        recon_snaps = reg.list_snapshots(runtime="pi-semantic-recon")
        assert len(recon_snaps) == 1
        assert recon_snaps[0].runtime == "pi-semantic-recon"


def test_lineage_chain() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        reg = SnapshotRegistry(Path(tmp))
        parent = reg.store_snapshot("recon", "exec_1", {"a": 1})
        child = reg.store_snapshot("recon", "exec_2", {"b": 2}, lineage_parent=parent.metadata.snapshot_id)
        chain = reg.lineage(child.metadata.snapshot_id)
        assert len(chain) == 1
        assert chain[0].snapshot_id == parent.metadata.snapshot_id


def test_retention_enforcement() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        policy = RetentionPolicy(max_snapshots=2, max_replay_bundles=2)
        reg = SnapshotRegistry(Path(tmp), policy=policy)
        reg.store_snapshot("recon", "exec_1", {"a": 1})
        reg.store_snapshot("recon", "exec_2", {"b": 2})
        reg.store_snapshot("recon", "exec_3", {"c": 3})
        snaps = reg.list_snapshots()
        assert len(snaps) <= policy.max_snapshots
