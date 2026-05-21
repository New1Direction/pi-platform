"""Central Orchestration Kernel.

Single authoritative scheduler. Deterministic work routing. Replay-aware execution ordering.
Bounded worker pools. No decentralized planning.

No inference. No LLM calls. No probabilistic routing.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus
from pi_interoperability_layer.mesh.receipts import (
    ExecutionReceipt,
    OrchestrationLedger,
    PhaseBoundaryReceipt,
)
from pi_interoperability_layer.mesh.worker_base import WorkerBase, WorkerContract


class PhaseConfig:
    """Immutable configuration for an orchestration phase."""

    def __init__(
        self,
        phase_name: str,
        worker_classes: List[Type[WorkerBase]],
        max_fanout: int = 8,
        required_worker_ids: Optional[List[str]] = None,
    ) -> None:
        self.phase_name = phase_name
        self.worker_classes = worker_classes
        self.max_fanout = max_fanout
        self.required_worker_ids = required_worker_ids or []


class CentralOrchestratorKernel:
    """Central scheduler with fixed phases and deterministic merge."""

    PHASE_ORDER = [
        "INGEST",
        "EXTRACT",
        "DIFF",
        "VALIDATE",
        "RISK",
        "GOVERN",
        "EMIT",
    ]

    def __init__(
        self,
        pipeline_name: str,
        bus: ArtifactBus,
        ledger: OrchestrationLedger,
        phases: Optional[List[PhaseConfig]] = None,
        fail_open: bool = False,
    ) -> None:
        self.pipeline_name = pipeline_name
        self.bus = bus
        self.ledger = ledger
        self.phases = {p.phase_name: p for p in (phases or [])}
        self.fail_open = fail_open
        self._workers: Dict[str, WorkerBase] = {}
        self._phase_index = 0

    def register_worker(self, worker: WorkerBase) -> None:
        if worker.worker_id in self._workers:
            raise ValueError(f"Worker already registered: {worker.worker_id}")
        self._workers[worker.worker_id] = worker

    def run_pipeline(self, initial_slot_ids: List[str]) -> OrchestrationLedger:
        for phase_name in self.PHASE_ORDER:
            config = self.phases.get(phase_name)
            if config is None:
                # Phase not configured: create empty boundary and continue
                boundary = PhaseBoundaryReceipt(phase=phase_name, phase_status="SUCCESS")
                self.ledger.append_boundary(boundary)
                continue

            phase_inputs = self._resolve_phase_inputs(phase_name, initial_slot_ids)
            receipts = self._run_phase(config, phase_inputs)

            # Deterministic merge: check all required workers produced receipts
            merge_status = self._merge_phase(config, receipts)
            boundary = PhaseBoundaryReceipt(
                phase=phase_name,
                worker_receipt_ids=[r.receipt_id for r in receipts],
                phase_status=merge_status,
            )
            self.ledger.append_boundary(boundary)

            if merge_status == "FAIL" and not self.fail_open:
                self.ledger.close()
                return self.ledger

        self.ledger.close()
        return self.ledger

    def _resolve_phase_inputs(self, phase_name: str, initial_slot_ids: List[str]) -> List[str]:
        if phase_name == "INGEST":
            return initial_slot_ids
        # Subsequent phases consume outputs from previous phase boundary
        prev_idx = self.PHASE_ORDER.index(phase_name) - 1
        prev_phase = self.PHASE_ORDER[prev_idx]
        boundary = self.ledger.last_boundary_for_phase(prev_phase)
        if boundary is None or boundary.merged_output_slot_id is None:
            return []
        return [boundary.merged_output_slot_id]

    def _run_phase(self, config: PhaseConfig, input_slot_ids: List[str]) -> List[ExecutionReceipt]:
        receipts: List[ExecutionReceipt] = []
        # Instantiate workers deterministically by class
        for i, cls in enumerate(config.worker_classes):
            worker_id = f"{config.phase_name}_{cls.__name__}_{i}"
            contract = WorkerContract(worker_class=cls.__name__)
            worker = cls(worker_id, contract, self.bus, self.ledger)
            receipt = worker.execute(config.phase_name, input_slot_ids)
            receipts.append(receipt)
            if len(receipts) >= config.max_fanout:
                break
        return receipts

    def _merge_phase(self, config: PhaseConfig, receipts: List[ExecutionReceipt]) -> str:
        # Check required workers
        for req_id in config.required_worker_ids:
            found = any(r.worker_id == req_id and r.status == "SUCCESS" for r in receipts)
            if not found:
                return "FAIL"
        # Check any failure
        for r in receipts:
            if r.status in ("FAIL", "PANIC", "SCHEMA_MISMATCH", "REPLAY_MISMATCH"):
                return "FAIL"
            if r.status == "TIMEOUT" and not self.fail_open:
                return "FAIL"
            if r.status == "RESOURCE_EXCEEDED" and not self.fail_open:
                return "FAIL"
        return "SUCCESS"

    def current_phase(self) -> Optional[str]:
        if self._phase_index < len(self.PHASE_ORDER):
            return self.PHASE_ORDER[self._phase_index]
        return None
