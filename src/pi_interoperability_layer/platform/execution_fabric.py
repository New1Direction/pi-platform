"""Shard-Coordinated Deterministic Execution Fabric.

⚠️  SIMULATION / REFERENCE SCAFFOLD — NOT a live execution path.

This models the *shape* of a compiler-style distributed fabric (deterministic
partitioning, phase-locked orchestration, worker leasing, replay recovery), but
``execute_phase`` does NOT distribute or run anything: it resolves every step to
a hash of the input via ``_simulate_execution`` (see the "# simulated" markers).
It has no production caller — only its own unit/integration tests import it. Do
not treat it as evidence that real distributed/barrier execution exists. Wire it
to a real dispatcher, or move it under an examples/ namespace, before relying on
it as a platform capability.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.manifest import ExtensionManifest

# ── Execution Phase ──────────────────────────────────────────────


class ExecutionPhase(str, Enum):
    PENDING = "pending"
    SCHEDULING = "scheduling"
    RUNNING = "running"
    BARRIER_WAIT = "barrier_wait"
    COMPLETED = "completed"
    FAILED = "failed"
    REPLAYING = "replaying"


# ── Worker Lease ─────────────────────────────────────────────────


@dataclass(frozen=True)
class WorkerLease:
    """Ephemeral execution lease for a deterministic worker.

    Workers are leased per-phase. No worker survives across
    phases without explicit re-assignment.
    """

    lease_id: str
    worker_id: str
    shard_id: str
    phase_number: int
    manifest_id: str
    leased_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = ""  # empty means no expiration (bounded by phase completion)
    cpu_ms_max: int = 5000
    memory_mb_max: int = 256
    output_size_max: int = 10 * 1024 * 1024

    def compute_hash(self) -> str:
        # Content-addressed identity hash. Excludes the random lease_id/worker_id
        # (uuid4-derived) and the wall-clock leased_at so the same logical lease
        # reproduces the same hash across runs. All three remain STORED on the
        # lease as metadata.
        data = json.dumps(
            {
                "shard_id": self.shard_id,
                "phase_number": self.phase_number,
                "manifest_id": self.manifest_id,
                "cpu_ms_max": self.cpu_ms_max,
                "memory_mb_max": self.memory_mb_max,
                "output_size_max": self.output_size_max,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


# ── Phase Barrier ────────────────────────────────────────────────


@dataclass(frozen=True)
class PhaseBarrier:
    """Global synchronization point for a distributed execution phase.

    All shards must report COMPLETED or FAILED before the
    coordinator advances to the next phase.
    """

    phase_number: int
    total_shards: int
    completed_shards: Tuple[str, ...] = field(default_factory=tuple)
    failed_shards: Tuple[str, ...] = field(default_factory=tuple)
    phase_hash: str = ""  # hash of all worker outputs in this phase
    barrier_status: str = "open"  # open, closed, aborted

    def all_complete(self) -> bool:
        return len(self.completed_shards) == self.total_shards and len(self.failed_shards) == 0

    def any_failed(self) -> bool:
        return len(self.failed_shards) > 0

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "phase_number": self.phase_number,
                "total_shards": self.total_shards,
                "completed": sorted(self.completed_shards),
                "failed": sorted(self.failed_shards),
                "phase_hash": self.phase_hash,
                "barrier_status": self.barrier_status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


# ── Execution Receipt ────────────────────────────────────────────


@dataclass(frozen=True)
class PhaseExecutionReceipt:
    phase_number: int
    shard_id: str
    worker_id: str
    lease_id: str
    status: str  # completed, failed, skipped
    output_hash: str = ""
    evidence: str = ""
    duration_ms: int = 0

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "phase_number": self.phase_number,
                "shard_id": self.shard_id,
                "worker_id": self.worker_id,
                "lease_id": self.lease_id,
                "status": self.status,
                "output_hash": self.output_hash,
                "evidence": self.evidence,
                "duration_ms": self.duration_ms,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass(frozen=True)
class ExecutionFabricReceipt:
    execution_id: str
    pipeline_hash: str
    total_phases: int
    phases_completed: int
    phases_failed: int
    final_status: str  # success, partial_failure, total_failure
    phase_receipts: Tuple[PhaseExecutionReceipt, ...]
    barrier_hashes: Tuple[str, ...]
    replay_hash: str = ""  # deterministic hash for full replay

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "execution_id": self.execution_id,
                "pipeline_hash": self.pipeline_hash,
                "total_phases": self.total_phases,
                "phases_completed": self.phases_completed,
                "phases_failed": self.phases_failed,
                "final_status": self.final_status,
                "phase_receipts": [r.compute_hash() for r in self.phase_receipts],
                "barrier_hashes": list(self.barrier_hashes),
                "replay_hash": self.replay_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


# ── Shard-Coordinated Execution Fabric ───────────────────────────


class DeterministicExecutionFabric:
    """Distributed deterministic execution with global barriers.

    NOT a swarm. NOT autonomous. This is a compiler-style
    distributed scheduler where a central coordinator assigns
    work to deterministic shards, waits for ALL shards at
    each phase boundary, then advances.

    Key properties:
    - SHA256 deterministic shard assignment
    - Phase-locked advancement (global barrier)
    - Ephemeral worker leasing (workers die with phase)
    - Failure isolation per shard
    - Replay recovery from deterministic inputs
    """

    def __init__(self, shard_count: int = 4) -> None:
        self.shard_count = shard_count
        self._shards: Dict[str, Any] = {}  # shard_id → manifest assignments
        self._leases: Dict[str, WorkerLease] = {}
        self._phase_receipts: Dict[int, List[PhaseExecutionReceipt]] = {}
        self._barriers: Dict[int, PhaseBarrier] = {}
        self._execution_log: List[ExecutionFabricReceipt] = []

    # ── Deterministic Shard Assignment ───────────────────────────

    def assign_to_shard(self, manifest_id: str) -> str:
        """Deterministically assign a manifest to a shard via SHA256.

        Identical inputs always produce identical shard assignments.
        """
        hash_val = hashlib.sha256(manifest_id.encode()).hexdigest()
        shard_index = int(hash_val[:16], 16) % self.shard_count
        shard_id = f"shard-{shard_index:04d}"
        assignments = self._shards.setdefault(shard_id, [])
        if manifest_id not in assignments:
            assignments.append(manifest_id)
        return shard_id

    def get_shard_assignments(self, shard_id: str) -> Tuple[str, ...]:
        return tuple(self._shards.get(shard_id, []))

    # ── Worker Leasing ───────────────────────────────────────────

    def lease_worker(
        self,
        shard_id: str,
        manifest_id: str,
        phase_number: int,
        cpu_ms: int = 5000,
        memory_mb: int = 256,
    ) -> WorkerLease:
        """Lease an ephemeral worker for a single phase.

        Workers are NOT persistent. They exist only for the
        duration of one phase and are reclaimed at barrier.
        """
        lease = WorkerLease(
            lease_id=f"lease_{uuid.uuid4().hex[:16]}",
            worker_id=f"worker_{uuid.uuid4().hex[:16]}",
            shard_id=shard_id,
            phase_number=phase_number,
            manifest_id=manifest_id,
            cpu_ms_max=cpu_ms,
            memory_mb_max=memory_mb,
        )
        self._leases[lease.lease_id] = lease
        return lease

    def release_lease(self, lease_id: str) -> Optional[WorkerLease]:
        return self._leases.pop(lease_id, None)

    # ── Phase-Locked Execution ───────────────────────────────────

    def execute_phase(
        self,
        phase_number: int,
        manifests: List[ExtensionManifest],
    ) -> ExecutionFabricReceipt:
        """Execute a single phase with global barrier.

        Flow:
        1. Assign all manifests to shards (deterministic)
        2. Lease workers per shard
        3. Execute work in each shard (simulated)
        4. Wait at barrier for ALL shards
        5. Collect receipts
        6. Advance or fail

        In production, steps 3-4 would be distributed across nodes.
        Here we simulate the coordinator's view.
        """
        receipts: List[PhaseExecutionReceipt] = []
        barrier = PhaseBarrier(
            phase_number=phase_number,
            total_shards=self.shard_count,
        )

        # 1. Assign manifests to shards
        shard_assignments: Dict[str, List[ExtensionManifest]] = {f"shard-{i:04d}": [] for i in range(self.shard_count)}
        for manifest in manifests:
            shard_id = self.assign_to_shard(manifest.extension_id)
            shard_assignments[shard_id].append(manifest)

        # 2-4. Lease workers, execute, and report to barrier
        for shard_id, assigned_manifests in shard_assignments.items():
            for manifest in assigned_manifests:
                lease = self.lease_worker(shard_id, manifest.extension_id, phase_number)
                # Simulate execution (in production this would dispatch to a worker node)
                output_hash = self._simulate_execution(manifest, lease)
                receipt = PhaseExecutionReceipt(
                    phase_number=phase_number,
                    shard_id=shard_id,
                    worker_id=lease.worker_id,
                    lease_id=lease.lease_id,
                    status="completed",
                    output_hash=output_hash,
                    evidence=f"Executed {manifest.extension_id} on {shard_id}",
                    duration_ms=10,  # simulated
                )
                receipts.append(receipt)
                self.release_lease(lease.lease_id)

        # Build phase hash from all receipts
        phase_hash = self._compute_phase_hash(receipts)
        # All shards must report to the barrier (even empty ones complete)
        all_completed = tuple(f"shard-{i:04d}" for i in range(self.shard_count))
        barrier = PhaseBarrier(
            phase_number=phase_number,
            total_shards=self.shard_count,
            completed_shards=all_completed,
            phase_hash=phase_hash,
            barrier_status="closed",
        )

        # Store receipts and barrier
        self._phase_receipts[phase_number] = receipts
        self._barriers[phase_number] = barrier

        fabric_receipt = ExecutionFabricReceipt(
            execution_id=f"exec_{uuid.uuid4().hex[:16]}",
            pipeline_hash=phase_hash,
            total_phases=1,
            phases_completed=len(receipts),
            phases_failed=0,
            final_status="success",
            phase_receipts=tuple(receipts),
            barrier_hashes=(barrier.compute_hash(),),
            replay_hash=phase_hash,
        )
        self._execution_log.append(fabric_receipt)
        return fabric_receipt

    def execute_dag(
        self,
        execution_id: str,
        phases: List[List[ExtensionManifest]],
    ) -> ExecutionFabricReceipt:
        """Execute a multi-phase DAG with barriers between each phase.

        All phases must succeed for the DAG to complete.
        Fail-closed: any phase failure aborts the entire execution.
        """
        all_receipts: List[PhaseExecutionReceipt] = []
        all_barriers: List[str] = []
        total_completed = 0
        total_failed = 0

        for phase_num, manifest_list in enumerate(phases, start=1):
            phase_receipt = self.execute_phase(phase_num, manifest_list)
            all_receipts.extend(phase_receipt.phase_receipts)
            all_barriers.extend(phase_receipt.barrier_hashes)

            if phase_receipt.final_status == "success":
                total_completed += len(phase_receipt.phase_receipts)
            else:
                total_failed += len(phase_receipt.phase_receipts)
                # Fail-closed: abort immediately
                break

        final_status = "success" if total_failed == 0 else "total_failure"
        full_replay_hash = self._compute_replay_hash(all_receipts)

        fabric_receipt = ExecutionFabricReceipt(
            execution_id=execution_id,
            pipeline_hash=full_replay_hash,
            total_phases=len(phases),
            phases_completed=total_completed,
            phases_failed=total_failed,
            final_status=final_status,
            phase_receipts=tuple(all_receipts),
            barrier_hashes=tuple(all_barriers),
            replay_hash=full_replay_hash,
        )
        return fabric_receipt

    # ── Replay Recovery ──────────────────────────────────────────

    def replay_execution(self, execution_id: str, replay_hash: str) -> ExecutionFabricReceipt:
        """Replay an execution from its deterministic hash.

        Replay verification: if the same inputs produce a different
        hash, determinism has been violated.
        """
        # Find the original execution
        original = None
        for rec in self._execution_log:
            if rec.execution_id == execution_id and rec.replay_hash == replay_hash:
                original = rec
                break
        if not original:
            raise ValueError(f"No execution found with id={execution_id} hash={replay_hash}")

        # In production, this would re-execute all phases and compare hashes
        # Here we verify the replay hash matches
        return original

    # ── Internal helpers ─────────────────────────────────────────

    def _simulate_execution(self, manifest: ExtensionManifest, lease: WorkerLease) -> str:
        """Simulate deterministic execution of a manifest within lease bounds."""
        payload = {
            "manifest_id": manifest.extension_id,
            "shard_id": lease.shard_id,
            "phase": lease.phase_number,
            "cpu_ms": lease.cpu_ms_max,
            "memory_mb": lease.memory_mb_max,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _compute_phase_hash(self, receipts: List[PhaseExecutionReceipt]) -> str:
        # Use only deterministic fields: output_hash + phase_number + shard_id + status
        hashes = sorted([f"{r.phase_number}:{r.shard_id}:{r.status}:{r.output_hash}" for r in receipts])
        return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()

    def _compute_replay_hash(self, receipts: List[PhaseExecutionReceipt]) -> str:
        hashes = sorted([f"{r.phase_number}:{r.shard_id}:{r.status}:{r.output_hash}" for r in receipts])
        return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


# ── Execution Audit ──────────────────────────────────────────────


class ExecutionAuditLog:
    """Append-only audit log for all execution fabric events."""

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def log(self, execution_id: str, event_type: str, detail: str, evidence_hash: str = "") -> None:
        self._events.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_id": execution_id,
                "event_type": event_type,
                "detail": detail,
                "evidence_hash": evidence_hash,
            }
        )

    def get_events(self, execution_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        events = self._events
        if execution_id:
            events = [e for e in events if e["execution_id"] == execution_id]
        return events[-limit:]
