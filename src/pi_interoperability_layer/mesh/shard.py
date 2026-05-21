"""Distributed Shard Coordinator.

Deterministic worker partitioning, bounded replay coordination,
and phase-locked orchestration across shards.

Centralized governance authority preserved.
No emergent behavior. No decentralized planning.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class ShardState(Enum):
    IDLE = "idle"
    ASSIGNED = "assigned"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class ShardAssignment:
    worker_id: str
    shard_id: str
    assignment_hash: str = ""

    def compute_hash(self) -> str:
        return hashlib.sha256(
            f"{self.worker_id}:{self.shard_id}".encode()
        ).hexdigest()


@dataclass(frozen=True)
class PhaseBoundary:
    phase: str
    shard_id: str
    worker_ids: Tuple[str, ...]
    completed: bool = False
    boundary_hash: str = ""

    def compute_hash(self) -> str:
        payload = (
            f"{self.phase}:{self.shard_id}:"
            f"{','.join(sorted(self.worker_ids))}:"
            f"{'1' if self.completed else '0'}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class DeterministicPartitioner:
    """Maps workers to shards deterministically.

    Same worker_id + same shard_count = same shard assignment.
    """

    def __init__(self, shard_count: int, shard_ids: Optional[List[str]] = None):
        self.shard_count = shard_count
        self.shard_ids = shard_ids or [f"shard_{i}" for i in range(shard_count)]
        if len(self.shard_ids) != shard_count:
            raise ValueError("shard_ids length must equal shard_count")

    def assign(self, worker_id: str) -> ShardAssignment:
        h = hashlib.sha256(worker_id.encode()).hexdigest()
        idx = int(h[:8], 16) % self.shard_count
        shard_id = self.shard_ids[idx]
        assignment = ShardAssignment(worker_id=worker_id, shard_id=shard_id)
        object.__setattr__(assignment, "assignment_hash", assignment.compute_hash())
        return assignment

    def assign_all(self, worker_ids: List[str]) -> Dict[str, ShardAssignment]:
        return {wid: self.assign(wid) for wid in worker_ids}


class ShardCoordinator:
    """Coordinates deterministic distributed execution.

    Phase-locked: all shards must complete a phase before global advance.
    Replay-safe: events ordered by deterministic shard sequence.
    Bounded: max workers per shard enforced.
    """

    def __init__(
        self,
        partitioner: DeterministicPartitioner,
        max_workers_per_shard: int = 32,
    ):
        self.partitioner = partitioner
        self.max_workers_per_shard = max_workers_per_shard
        self._shard_workers: Dict[str, Set[str]] = {sid: set() for sid in partitioner.shard_ids}
        self._shard_states: Dict[str, ShardState] = dict.fromkeys(partitioner.shard_ids, ShardState.IDLE)
        self._phase_boundaries: List[PhaseBoundary] = []
        self._execution_log: List[str] = []
        self._current_phase: Optional[str] = None

    def register_workers(self, worker_ids: List[str]) -> Dict[str, ShardAssignment]:
        assignments = self.partitioner.assign_all(worker_ids)
        for wid, assignment in assignments.items():
            shard = assignment.shard_id
            if len(self._shard_workers[shard]) >= self.max_workers_per_shard:
                raise ValueError(
                    f"Shard {shard} exceeds max_workers_per_shard ({self.max_workers_per_shard})"
                )
            self._shard_workers[shard].add(wid)
            self._execution_log.append(f"REGISTER {wid} -> {shard}")
        return assignments

    def begin_phase(self, phase: str) -> None:
        self._current_phase = phase
        for sid in self.partitioner.shard_ids:
            self._shard_states[sid] = ShardState.EXECUTING
        self._execution_log.append(f"PHASE_BEGIN {phase}")

    def mark_shard_completed(self, shard_id: str) -> None:
        if shard_id not in self._shard_states:
            raise KeyError(f"Unknown shard: {shard_id}")
        self._shard_states[shard_id] = ShardState.COMPLETED
        self._execution_log.append(f"SHARD_COMPLETE {shard_id}")

    def can_advance_phase(self) -> bool:
        return all(s == ShardState.COMPLETED for s in self._shard_states.values())

    def advance_phase(self, next_phase: str) -> PhaseBoundary:
        if not self.can_advance_phase():
            raise RuntimeError("Cannot advance: not all shards completed current phase")
        workers = tuple(sorted(
            wid for workers in self._shard_workers.values() for wid in workers
        ))
        boundary = PhaseBoundary(
            phase=self._current_phase or "INGEST",
            shard_id="global",
            worker_ids=workers,
            completed=True,
        )
        object.__setattr__(boundary, "boundary_hash", boundary.compute_hash())
        self._phase_boundaries.append(boundary)
        self._execution_log.append(f"PHASE_ADVANCE {boundary.phase} {boundary.boundary_hash}")
        # Reset shard states
        for sid in self.partitioner.shard_ids:
            self._shard_states[sid] = ShardState.IDLE
        self._current_phase = next_phase
        return boundary

    def replay_sequence(self) -> List[Tuple[str, List[str]]]:
        """Return deterministic execution order for replay:
        (shard_id, [worker_ids_in_shard]) per phase.
        """
        sequence: List[Tuple[str, List[str]]] = []
        for sid in sorted(self.partitioner.shard_ids):
            workers = sorted(self._shard_workers.get(sid, set()))
            if workers:
                sequence.append((sid, workers))
        return sequence

    def get_shard_for_worker(self, worker_id: str) -> str:
        for sid, workers in self._shard_workers.items():
            if worker_id in workers:
                return sid
        raise KeyError(f"Worker {worker_id} not registered")

    def verify_assignment_determinism(self, worker_ids: List[str]) -> bool:
        """Verify that re-assignment produces identical results."""
        first = self.partitioner.assign_all(worker_ids)
        second = self.partitioner.assign_all(worker_ids)
        return all(
            first[wid].shard_id == second[wid].shard_id
            and first[wid].assignment_hash == second[wid].assignment_hash
            for wid in worker_ids
        )

    def execution_log(self) -> List[str]:
        return list(self._execution_log)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "shard_count": self.partitioner.shard_count,
            "shard_ids": self.partitioner.shard_ids,
            "max_workers_per_shard": self.max_workers_per_shard,
            "shard_workers": {sid: sorted(workers) for sid, workers in self._shard_workers.items()},
            "shard_states": {sid: state.value for sid, state in self._shard_states.items()},
            "current_phase": self._current_phase if self._current_phase else None,
            "phase_boundaries": [b.boundary_hash for b in self._phase_boundaries],
            "execution_log": self._execution_log,
        }
