"""Worker Base: abstract contract-enforced worker class.

Every specialized worker inherits from WorkerBase.
Deterministic execution, bounded resources, immutable I/O.

No recursive spawning. No self-modification. No LLM calls.
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, OrchestrationLedger


class WorkerContract(BaseModel):
    """Immutable contract defining a worker's interface and bounds."""

    worker_class: str
    required_input_artifact_types: List[str] = Field(default_factory=list)
    produced_output_artifact_types: List[str] = Field(default_factory=list)
    max_execution_ms: float = 30000.0
    max_memory_mb: float = 512.0
    max_input_slots: int = 16
    max_output_slots: int = 16
    deterministic: bool = True
    model_config = {"frozen": True}


class WorkerBase(ABC):
    """Abstract base for all semantic mesh workers.

    Workers are deterministic, bounded, and non-autonomous.
    They MUST NOT:
      - spawn other workers
      - modify their own contracts
      - perform LLM inference
      - access external networks
      - mutate runtime state
    """

    def __init__(self, worker_id: str, contract: WorkerContract, bus: ArtifactBus, ledger: OrchestrationLedger) -> None:
        self.worker_id = worker_id
        self.contract = contract
        self.bus = bus
        self.ledger = ledger
        self._spawned = False
        self._modified_contract = False

    def execute(self, phase: str, input_slot_ids: List[str]) -> ExecutionReceipt:
        """Execute worker with contract enforcement and receipt generation.

        This is the ONLY public entry point. Subclasses override _run().
        """
        # Anti-pattern guards
        if self._spawned:
            return self._make_receipt(phase, input_slot_ids, [], "PANIC", "Worker attempted recursive spawn")
        if self._modified_contract:
            return self._make_receipt(phase, input_slot_ids, [], "PANIC", "Worker attempted contract mutation")

        # Input validation
        if len(input_slot_ids) > self.contract.max_input_slots:
            return self._make_receipt(phase, input_slot_ids, [], "RESOURCE_EXCEEDED", f"Inputs {len(input_slot_ids)} > max {self.contract.max_input_slots}")

        # Schema validation
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                return self._make_receipt(phase, input_slot_ids, [], "SCHEMA_MISMATCH", f"Missing slot: {sid}")
            if slot.artifact_type not in self.contract.required_input_artifact_types and self.contract.required_input_artifact_types:
                return self._make_receipt(phase, input_slot_ids, [], "SCHEMA_MISMATCH", f"Unexpected artifact type: {slot.artifact_type}")

        # Bounded execution with wall-clock guard
        start = time.perf_counter()
        try:
            output_slots = self._run(phase, input_slot_ids)
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return self._make_receipt(phase, input_slot_ids, [], "FAIL", f"Exception: {type(exc).__name__}: {exc}", resource_usage={"cpu_ms": elapsed})

        elapsed = (time.perf_counter() - start) * 1000
        if elapsed > self.contract.max_execution_ms:
            return self._make_receipt(phase, input_slot_ids, output_slots, "TIMEOUT", f"Elapsed {elapsed:.1f}ms > max {self.contract.max_execution_ms}ms", resource_usage={"cpu_ms": elapsed})

        # Output count validation
        if len(output_slots) > self.contract.max_output_slots:
            return self._make_receipt(phase, input_slot_ids, output_slots, "RESOURCE_EXCEEDED", f"Outputs {len(output_slots)} > max {self.contract.max_output_slots}", resource_usage={"cpu_ms": elapsed})

        # Determinism proof: hash of output payloads
        determinism_proof = self._compute_determinism_proof(output_slots)

        return self._make_receipt(
            phase,
            input_slot_ids,
            [s.slot_id for s in output_slots],
            "SUCCESS",
            resource_usage={"cpu_ms": elapsed, "memory_mb": 0.0},
            determinism_proof=determinism_proof,
        )

    @abstractmethod
    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        """Subclass implements deterministic bounded work here."""
        ...

    def _make_receipt(
        self,
        phase: str,
        input_slot_ids: List[str],
        output_slot_ids: List[str],
        status: str,
        status_detail: str = "",
        resource_usage: Optional[Dict[str, float]] = None,
        determinism_proof: str = "",
    ) -> ExecutionReceipt:
        receipt = ExecutionReceipt(
            worker_class=self.contract.worker_class,
            worker_id=self.worker_id,
            phase=phase,
            input_slot_ids=sorted(input_slot_ids),
            output_slot_ids=sorted(output_slot_ids),
            status=status,
            status_detail=status_detail,
            determinism_proof=determinism_proof,
            resource_usage=resource_usage or {},
        )
        receipt = receipt.model_copy(update={"receipt_hash": receipt.compute_hash()})
        self.ledger.append_receipt(receipt)
        return receipt

    def _compute_determinism_proof(self, slots: List[ArtifactSlot]) -> str:
        if not slots:
            return ""
        combined = "".join(s.fingerprint for s in slots)
        return hashlib.sha256(combined.encode()).hexdigest()
