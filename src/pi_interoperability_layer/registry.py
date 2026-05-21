"""Immutable Snapshot / Replay Registry.

Deterministic storage, retrieval, and retention of semantic snapshots,
replay bundles, and topology lineage.

No inference. No LLM calls. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SnapshotMetadata(BaseModel):
    snapshot_id: str
    runtime: str  # e.g. "pi-semantic-recon", "pi-semantic-diff"
    execution_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifact_hash: str
    lineage_parent: Optional[str] = None
    model_config = {"frozen": True}


class SnapshotRecord(BaseModel):
    metadata: SnapshotMetadata
    payload: Dict[str, Any]
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload_bytes = json.dumps(self.payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(payload_bytes).hexdigest()


class ReplayBundle(BaseModel):
    bundle_id: str
    baseline_snapshot_id: str
    modified_snapshot_id: str
    diff_report_id: str
    risk_report_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    bundle_hash: str = ""
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = self.model_dump(exclude={"bundle_hash"})
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(payload_bytes).hexdigest()


class RetentionPolicy(BaseModel):
    max_snapshots: int = 1000
    max_age_days: int = 90
    max_replay_bundles: int = 500
    model_config = {"frozen": True}


class SnapshotRegistry:
    """Deterministic snapshot/replay registry with retention enforcement."""

    def __init__(self, root_dir: Path, policy: Optional[RetentionPolicy] = None) -> None:
        self.root = Path(root_dir)
        self.snapshots_dir = self.root / "snapshots"
        self.bundles_dir = self.root / "bundles"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy or RetentionPolicy()

    def store_snapshot(self, runtime: str, execution_id: str, payload: Dict[str, Any], lineage_parent: Optional[str] = None) -> SnapshotRecord:
        artifact_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        snapshot_id = f"snap_{runtime}_{execution_id}_{artifact_hash[:16]}"
        meta = SnapshotMetadata(
            snapshot_id=snapshot_id,
            runtime=runtime,
            execution_id=execution_id,
            artifact_hash=artifact_hash,
            lineage_parent=lineage_parent,
        )
        record = SnapshotRecord(metadata=meta, payload=payload)
        path = self.snapshots_dir / f"{snapshot_id}.json"
        with open(path, "w") as f:
            json.dump(record.model_dump(), f, indent=2, default=str)
        self._enforce_retention()
        return record

    def load_snapshot(self, snapshot_id: str) -> Optional[SnapshotRecord]:
        path = self.snapshots_dir / f"{snapshot_id}.json"
        if not path.exists():
            return None
        with open(path, "r") as f:
            data = json.load(f)
        return SnapshotRecord(**data)

    def store_bundle(self, baseline_snapshot_id: str, modified_snapshot_id: str, diff_report_id: str, risk_report_id: Optional[str] = None) -> ReplayBundle:
        bundle = ReplayBundle(
            bundle_id=f"bundle_{uuid.uuid4().hex[:16]}",
            baseline_snapshot_id=baseline_snapshot_id,
            modified_snapshot_id=modified_snapshot_id,
            diff_report_id=diff_report_id,
            risk_report_id=risk_report_id,
        )
        bundle = bundle.model_copy(update={"bundle_hash": bundle.compute_hash()})
        path = self.bundles_dir / f"{bundle.bundle_id}.json"
        with open(path, "w") as f:
            json.dump(bundle.model_dump(), f, indent=2, default=str)
        self._enforce_retention()
        return bundle

    def load_bundle(self, bundle_id: str) -> Optional[ReplayBundle]:
        path = self.bundles_dir / f"{bundle_id}.json"
        if not path.exists():
            return None
        with open(path, "r") as f:
            data = json.load(f)
        return ReplayBundle(**data)

    def list_snapshots(self, runtime: Optional[str] = None) -> List[SnapshotMetadata]:
        records = []
        for path in sorted(self.snapshots_dir.glob("*.json")):
            with open(path, "r") as f:
                data = json.load(f)
            meta = SnapshotMetadata(**data["metadata"])
            if runtime is None or meta.runtime == runtime:
                records.append(meta)
        return records

    def list_bundles(self) -> List[ReplayBundle]:
        bundles = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            with open(path, "r") as f:
                data = json.load(f)
            bundles.append(ReplayBundle(**data))
        return bundles

    def lineage(self, snapshot_id: str) -> List[SnapshotMetadata]:
        """Return ancestor chain for a snapshot."""
        chain: List[SnapshotMetadata] = []
        current = self.load_snapshot(snapshot_id)
        visited: set = set()
        while current is not None and current.metadata.lineage_parent is not None:
            parent = self.load_snapshot(current.metadata.lineage_parent)
            if parent is None:
                break
            if parent.metadata.snapshot_id in visited:
                break
            visited.add(parent.metadata.snapshot_id)
            chain.append(parent.metadata)
            current = parent
        return list(reversed(chain))

    def _enforce_retention(self) -> None:
        now = datetime.now(timezone.utc)
        # Enforce snapshot count limit
        snapshots = sorted(self.snapshots_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        if len(snapshots) > self.policy.max_snapshots:
            for old in snapshots[:-self.policy.max_snapshots]:
                old.unlink()
        # Enforce snapshot age limit
        cutoff = now - timedelta(days=self.policy.max_age_days)
        for path in self.snapshots_dir.glob("*.json"):
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                path.unlink()
        # Enforce bundle count limit
        bundles = sorted(self.bundles_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        if len(bundles) > self.policy.max_replay_bundles:
            for old in bundles[:-self.policy.max_replay_bundles]:
                old.unlink()
