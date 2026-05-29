"""Tests for Semantic Worker Mesh orchestration.

Deterministic pipeline execution, contract enforcement, chain integrity.
"""

from __future__ import annotations

from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.kernel import CentralOrchestratorKernel, PhaseConfig
from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, OrchestrationLedger, PhaseBoundaryReceipt
from pi_interoperability_layer.mesh.worker_base import WorkerBase, WorkerContract
from pi_interoperability_layer.mesh.workers import (
    BoundaryValidationWorker,
    DependencyExtractionWorker,
    EndpointExtractionWorker,
    MergeGateWorker,
    SchemaValidationWorker,
    SnapshotIngestWorker,
)


class _DummyWorker(WorkerBase):
    def _run(self, phase: str, input_slot_ids: list[str]) -> list[ArtifactSlot]:
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="DummyOutput",
            payload={"phase": phase},
        ).freeze()
        return [self.bus.write(slot)]


class _FailingWorker(WorkerBase):
    def _run(self, phase: str, input_slot_ids: list[str]) -> list[ArtifactSlot]:
        raise ValueError("intentional failure")


class _TimeoutWorker(WorkerBase):
    def _run(self, phase: str, input_slot_ids: list[str]) -> list[ArtifactSlot]:
        import time

        time.sleep(0.001)
        return []


def test_artifact_bus_slot_versioning() -> None:
    bus = ArtifactBus()
    s1 = ArtifactSlot(producer_worker_id="w1", artifact_type="A", payload={"v": 1}).freeze()
    s2 = ArtifactSlot(producer_worker_id="w1", artifact_type="A", payload={"v": 2}).freeze()
    bus.write(s1)
    bus.write(s2)
    latest = bus.latest_for_family("A", "w1")
    assert latest is not None
    assert latest.fingerprint == s2.fingerprint


def test_artifact_bus_family_listing() -> None:
    bus = ArtifactBus()
    bus.write(ArtifactSlot(producer_worker_id="w1", artifact_type="A", payload={}).freeze())
    bus.write(ArtifactSlot(producer_worker_id="w2", artifact_type="B", payload={}).freeze())
    families = bus.list_families()
    assert len(families) == 2


def test_execution_receipt_chain_hashing() -> None:
    ledger = OrchestrationLedger(pipeline_name="test")
    r1 = ExecutionReceipt(worker_class="A", worker_id="w1", phase="INGEST")
    r1 = ledger.append_receipt(r1)
    r2 = ExecutionReceipt(worker_class="B", worker_id="w2", phase="EXTRACT")
    r2 = ledger.append_receipt(r2)
    assert r2.previous_receipt_hash == r1.receipt_hash
    assert ledger.verify_chain()


def test_phase_boundary_chain_hashing() -> None:
    ledger = OrchestrationLedger(pipeline_name="test")
    b1 = PhaseBoundaryReceipt(phase="INGEST", phase_status="SUCCESS")
    b1 = ledger.append_boundary(b1)
    b2 = PhaseBoundaryReceipt(phase="EXTRACT", phase_status="SUCCESS")
    b2 = ledger.append_boundary(b2)
    assert b2.previous_boundary_hash == b1.boundary_hash
    assert ledger.verify_chain()


def test_worker_contract_input_validation() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    contract = WorkerContract(worker_class="Test", required_input_artifact_types=["A"], max_input_slots=1)
    # Missing required type
    bad_slot = bus.write(ArtifactSlot(producer_worker_id="x", artifact_type="B", payload={}).freeze())
    worker = _DummyWorker("w1", contract, bus, ledger)
    receipt = worker.execute("TEST", [bad_slot.slot_id])
    assert receipt.status == "SCHEMA_MISMATCH"


def test_worker_contract_resource_ceiling() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    contract = WorkerContract(worker_class="Test", max_input_slots=0)
    worker = _DummyWorker("w1", contract, bus, ledger)
    slot = bus.write(ArtifactSlot(producer_worker_id="x", artifact_type="A", payload={}).freeze())
    receipt = worker.execute("TEST", [slot.slot_id])
    assert receipt.status == "RESOURCE_EXCEEDED"


def test_worker_failure_receipt() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    contract = WorkerContract(worker_class="Fail")
    worker = _FailingWorker("w1", contract, bus, ledger)
    receipt = worker.execute("TEST", [])
    assert receipt.status == "FAIL"
    assert "intentional failure" in receipt.status_detail


def test_orchestrator_kernel_empty_phases() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    kernel = CentralOrchestratorKernel("test", bus, ledger)
    result = kernel.run_pipeline([])
    assert result.closed_at is not None
    assert len(result.boundaries) == 7
    assert all(b.phase_status == "SUCCESS" for b in result.boundaries)


def test_orchestrator_kernel_with_workers() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    phases = [
        PhaseConfig("INGEST", [SnapshotIngestWorker, SchemaValidationWorker], max_fanout=8),
        PhaseConfig("EXTRACT", [EndpointExtractionWorker, DependencyExtractionWorker], max_fanout=8),
        PhaseConfig("VALIDATE", [BoundaryValidationWorker], max_fanout=8),
        PhaseConfig("EMIT", [MergeGateWorker], max_fanout=8),
    ]
    kernel = CentralOrchestratorKernel("test", bus, ledger, phases=phases)
    result = kernel.run_pipeline([])
    assert result.closed_at is not None
    ingest_boundary = result.last_boundary_for_phase("INGEST")
    assert ingest_boundary is not None
    assert ingest_boundary.phase_status == "SUCCESS"
    extract_receipts = result.receipts_for_phase("EXTRACT")
    assert len(extract_receipts) == 2
    # All receipts have determinism proofs
    for r in result.receipts:
        if r.status == "SUCCESS":
            assert r.determinism_proof != ""


def test_orchestrator_kernel_fail_closed() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    phases = [
        PhaseConfig("INGEST", [_FailingWorker], max_fanout=8),
    ]
    kernel = CentralOrchestratorKernel("test", bus, ledger, phases=phases, fail_open=False)
    result = kernel.run_pipeline([])
    boundary = result.last_boundary_for_phase("INGEST")
    assert boundary is not None
    assert boundary.phase_status == "FAIL"
    assert result.closed_at is not None


def test_orchestrator_kernel_fail_open() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    phases = [
        PhaseConfig("INGEST", [_FailingWorker], max_fanout=8),
        PhaseConfig("EXTRACT", [EndpointExtractionWorker], max_fanout=8),
    ]
    kernel = CentralOrchestratorKernel("test", bus, ledger, phases=phases, fail_open=True)
    result = kernel.run_pipeline([])
    boundary = result.last_boundary_for_phase("INGEST")
    assert boundary is not None
    assert boundary.phase_status == "FAIL"
    # EXTRACT still runs because fail_open=True
    extract_boundary = result.last_boundary_for_phase("EXTRACT")
    assert extract_boundary is not None
    assert extract_boundary.phase_status == "SUCCESS"


def test_ledger_verify_chain_detects_tampering() -> None:
    ledger = OrchestrationLedger(pipeline_name="test")
    r1 = ExecutionReceipt(worker_class="A", worker_id="w1", phase="INGEST")
    r1 = ledger.append_receipt(r1)
    # Tamper with receipt
    ledger.receipts[0] = ledger.receipts[0].model_copy(update={"status": "TAMPERED"})
    assert not ledger.verify_chain()


def test_merge_gate_blocked() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    # Pre-populate a failing boundary validation report
    fail_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="bv",
            artifact_type="BoundaryValidationReport",
            payload={"pass": False, "violations": [{}]},
        ).freeze()
    )
    contract = WorkerContract(worker_class="MergeGateWorker")
    worker = MergeGateWorker("mg1", contract, bus, ledger)
    receipt = worker.execute("EMIT", [fail_slot.slot_id])
    assert receipt.status == "SUCCESS"
    # Merge gate worker succeeds; its output slot contains BLOCKED status
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload.get("status") == "BLOCKED"


def test_endpoint_extraction_produces_traces() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    contract = WorkerContract(worker_class="EndpointExtractionWorker")
    worker = EndpointExtractionWorker("ee1", contract, bus, ledger)
    receipt = worker.execute("EXTRACT", [])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.artifact_type == "SemanticIRTrace"
    assert len(out.payload.get("traces", [])) == 2
