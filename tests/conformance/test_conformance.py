"""PI Runtime Specification Conformance Tests.

These tests verify that the reference implementation conforms to every
normative rule in PI-RUNTIME-SPEC-v1.0.md.

Run: PYTHONPATH=... pytest tests/test_conformance.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, Field, ValidationError

# ---------------------------------------------------------------------------
# Ensure all 6 runtime src/ dirs are on PYTHONPATH
# ---------------------------------------------------------------------------
DOCS = os.path.expanduser("~/Documents")
RUNTIMES = [
    "pi-agent-chain",
    "pi-semantic-diff",
    "pi-semantic-validator",
    "pi-semantic-radius",
    "pi-interoperability-layer",
    "pi-extension-governor",
]
for r in RUNTIMES:
    p = os.path.join(DOCS, r, "src")
    if p not in sys.path:
        sys.path.insert(0, p)

from pi_interoperability_layer.contracts import (
    ArtifactContract,
    ArtifactFingerprint,
    ContractRegistry,
    SchemaEvolutionLog,
    SchemaEvolutionRecord,
    SchemaVersion,
    canonical_json,
    compute_fingerprint,
)
from pi_interoperability_layer.execution import EventRecord, ExecutionEngine, ReplayLedger
from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, OrchestrationLedger, PhaseBoundaryReceipt
from pi_interoperability_layer.mesh.shard import DeterministicPartitioner, ShardCoordinator
from pi_interoperability_layer.mesh.worker_base import WorkerBase, WorkerContract
from pi_interoperability_layer.mesh.workers import SnapshotIngestWorker
from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest, ExtensionStatus, TrustZone
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_extension_governor.trust_zones import TrustZoneEnforcer
from pi_interoperability_layer.platform.tenant import Tenant, TenantRegistry, TenantStatus, TenantTier, ResourceQuota


# ===========================================================================
# CTEST-1: Artifact Immutability
# ===========================================================================
class TestArtifactImmutability:
    def test_frozen_model_rejects_mutation(self):
        ac = ArtifactContract(
            contract_id="test-1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="test",
        )
        with pytest.raises(ValidationError):
            ac.contract_id = "mutated"


# ===========================================================================
# CTEST-2: Deterministic Fingerprint
# ===========================================================================
class TestDeterministicFingerprint:
    def test_same_payload_same_hash(self):
        ac = ArtifactContract(
            contract_id="fp-1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="test",
        )
        fp1 = compute_fingerprint(ac, ac, generated_by="test")
        fp2 = compute_fingerprint(ac, ac, generated_by="test")
        assert fp1.content_hash == fp2.content_hash

    def test_different_payload_different_hash(self):
        ac1 = ArtifactContract(
            contract_id="fp-2",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="test",
        )
        ac2 = ArtifactContract(
            contract_id="fp-3",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="test2",
        )
        fp1 = compute_fingerprint(ac1, ac1, generated_by="test")
        fp2 = compute_fingerprint(ac2, ac2, generated_by="test")
        assert fp1.content_hash != fp2.content_hash


# ===========================================================================
# CTEST-3: Ledger Chain Integrity
# ===========================================================================
class TestLedgerChainIntegrity:
    def test_intact_ledger_verifies(self):
        ledger = ReplayLedger(ledger_id="L1", first_sequence=1, last_sequence=0)
        for i in range(5):
            ev = EventRecord(
                event_id=f"e{i}",
                event_type="ARTIFACT_RECEIVED",
                payload={"idx": i},
                emitted_by="test",
            )
            ledger.append(ev)
        assert ledger.verify_integrity()

    def test_tampered_ledger_fails(self):
        ledger = ReplayLedger(ledger_id="L2", first_sequence=1, last_sequence=0)
        ev = EventRecord(
            event_id="e0",
            event_type="ARTIFACT_RECEIVED",
            payload={"idx": 0},
            emitted_by="test",
        )
        linked = ledger.append(ev)
        # Mutate the stored event (bypass frozen model via internal list)
        original_hash = ledger.events[0].event_hash
        tampered = ledger.events[0].model_copy(update={"payload": {"idx": 999}})
        ledger.events[0] = tampered
        assert not ledger.verify_integrity()


# ===========================================================================
# CTEST-4: Receipt Chaining
# ===========================================================================
class TestReceiptChaining:
    def test_receipt_chain_verifies(self):
        ol = OrchestrationLedger(pipeline_name="test")
        for i in range(3):
            r = ExecutionReceipt(
                worker_class="TestWorker",
                worker_id=f"w{i}",
                phase="INGEST",
                input_slot_ids=[],
                output_slot_ids=[],
                status="SUCCESS",
            )
            ol.append_receipt(r)
        assert ol.verify_chain()

    def test_tampered_receipt_breaks_chain(self):
        ol = OrchestrationLedger(pipeline_name="test")
        r1 = ExecutionReceipt(
            worker_class="TestWorker",
            worker_id="w1",
            phase="INGEST",
            input_slot_ids=[],
            output_slot_ids=[],
            status="SUCCESS",
        )
        ol.append_receipt(r1)
        r2 = ExecutionReceipt(
            worker_class="TestWorker",
            worker_id="w2",
            phase="INGEST",
            input_slot_ids=[],
            output_slot_ids=[],
            status="SUCCESS",
        )
        ol.append_receipt(r2)
        # Tamper previous receipt hash
        bad = ol.receipts[1].model_copy(update={"previous_receipt_hash": "tampered"})
        ol.receipts[1] = bad
        assert not ol.verify_chain()


# ===========================================================================
# CTEST-5: Shard Determinism
# ===========================================================================
class TestShardDeterminism:
    def test_assignment_is_deterministic(self):
        dp = DeterministicPartitioner(shard_count=4)
        a1 = dp.assign("worker-alpha")
        for _ in range(10):
            a2 = dp.assign("worker-alpha")
            assert a1.shard_id == a2.shard_id
            assert a1.assignment_hash == a2.assignment_hash

    def test_recreated_partitioner_same_result(self):
        dp1 = DeterministicPartitioner(shard_count=4)
        dp2 = DeterministicPartitioner(shard_count=4)
        assert dp1.assign("w1").shard_id == dp2.assign("w1").shard_id


# ===========================================================================
# CTEST-6: Phase-Locked Advancement
# ===========================================================================
class TestPhaseLockedAdvancement:
    def test_cannot_advance_until_all_complete(self):
        dp = DeterministicPartitioner(shard_count=2)
        sc = ShardCoordinator(dp, max_workers_per_shard=8)
        sc.register_workers(["w1", "w2"])
        sc.begin_phase("EXTRACT")
        sc.mark_shard_completed("shard_0")
        assert not sc.can_advance_phase()
        sc.mark_shard_completed("shard_1")
        assert sc.can_advance_phase()


# ===========================================================================
# CTEST-7: Policy Fail-Closed
# ===========================================================================
class TestPolicyFailClosed:
    def test_empty_rules_deny(self):
        policy = ExtensionGovernancePolicy(
            approved_capability_classes=set(),
            allowed_trust_zones=set(),
        )
        manifest = ExtensionManifest(
            extension_id="ext-1",
            package_name="pkg",
            package_version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
        )
        result = policy.evaluate(manifest)
        assert not result.passed

    def test_missing_required_field_deny(self):
        policy = ExtensionGovernancePolicy(require_replay_safe=True)
        manifest = ExtensionManifest(
            extension_id="ext-2",
            package_name="pkg",
            package_version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            replayability_claim=False,
        )
        result = policy.evaluate(manifest)
        assert not result.passed

    def test_resource_exceeded_deny(self):
        policy = ExtensionGovernancePolicy(max_cpu_ms=100)
        manifest = ExtensionManifest(
            extension_id="ext-3",
            package_name="pkg",
            package_version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            resource_cpu_ms_max=500,
        )
        result = policy.evaluate(manifest)
        assert not result.passed


# ===========================================================================
# CTEST-8: Tenant Isolation
# ===========================================================================
class TestTenantIsolation:
    def test_capability_count_isolated(self):
        reg = TenantRegistry()
        t1 = Tenant(tenant_id="t1", tenant_name="T1", tier=TenantTier.STANDARD, status=TenantStatus.ACTIVE)
        t2 = Tenant(tenant_id="t2", tenant_name="T2", tier=TenantTier.STANDARD, status=TenantStatus.ACTIVE)
        reg.register(t1)
        reg.register(t2)
        reg.increment_capability("t1")
        e1 = reg.get("t1")
        e2 = reg.get("t2")
        assert e1.capability_count == 1
        assert e2.capability_count == 0

    def test_audit_log_isolated(self):
        reg = TenantRegistry()
        t1 = Tenant(tenant_id="t1", tenant_name="T1", status=TenantStatus.ACTIVE)
        reg.register(t1)
        reg._audit("t1", "TEST", "detail")
        log = reg.get_audit_log(tenant_id="t2")
        assert len(log) == 0


# ===========================================================================
# CTEST-9: ExplicitCompositionRequest Boundary
# (This is already tested extensively in pi-console/tests/backend/test_boundary.py;
# here we verify the schema contract at the spec level.)
# ===========================================================================
class TestExplicitCompositionRequestBoundary:
    def test_frozen_model_rejects_mutation(self):
        from pi_console.schemas import ExplicitCompositionRequest, CompositionNode

        req = ExplicitCompositionRequest(
            tenant_id="t1",
            console_session_id="s1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        with pytest.raises(ValidationError):
            req.tenant_id = "t2"

    def test_hash_is_deterministic(self):
        from pi_console.schemas import ExplicitCompositionRequest, CompositionNode

        req1 = ExplicitCompositionRequest(
            request_id="ecr_test_same",
            tenant_id="t1",
            console_session_id="s1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        ).with_hash()
        req2 = ExplicitCompositionRequest(
            request_id="ecr_test_same",
            tenant_id="t1",
            console_session_id="s1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        ).with_hash()
        assert req1.request_hash == req2.request_hash


# ===========================================================================
# CTEST-10: Replay Verification
# ===========================================================================
class TestReplayVerification:
    def test_worker_determinism_proof_matches(self):
        bus = ArtifactBus()
        ledger = OrchestrationLedger(pipeline_name="replay-test")

        class StableWorker(WorkerBase):
            def _run(self, phase, input_slot_ids):
                slot = ArtifactSlot(
                    producer_worker_id=self.worker_id,
                    artifact_type="TestOutput",
                    payload={"key": "value"},
                ).freeze()
                return [bus.write(slot)]

        contract = WorkerContract(worker_class="StableWorker", deterministic=True)
        w = StableWorker("w_stable", contract, bus, ledger)
        receipt1 = w.execute("INGEST", [])
        receipt2 = w.execute("INGEST", [])
        assert receipt1.determinism_proof == receipt2.determinism_proof


# ===========================================================================
# CTEST-11: Worker Contract Enforcement
# ===========================================================================
class TestWorkerContractEnforcement:
    def test_exceed_input_slots(self):
        bus = ArtifactBus()
        ledger = OrchestrationLedger(pipeline_name="contract-test")

        class DummyWorker(WorkerBase):
            def _run(self, phase, input_slot_ids):
                return []

        contract = WorkerContract(worker_class="DummyWorker", max_input_slots=2)
        w = DummyWorker("w1", contract, bus, ledger)
        r = w.execute("INGEST", ["s1", "s2", "s3"])
        assert r.status == "RESOURCE_EXCEEDED"

    def test_timeout_exceeded(self):
        bus = ArtifactBus()
        ledger = OrchestrationLedger(pipeline_name="contract-test")

        class SlowWorker(WorkerBase):
            def _run(self, phase, input_slot_ids):
                import time
                time.sleep(0.05)
                return []

        contract = WorkerContract(worker_class="SlowWorker", max_execution_ms=10)
        w = SlowWorker("w_slow", contract, bus, ledger)
        r = w.execute("INGEST", [])
        assert r.status == "TIMEOUT"


# ===========================================================================
# CTEST-12: Blast Radius Boundedness
# ===========================================================================
class TestBlastRadiusBoundedness:
    def test_limit_exceeded_detection(self):
        from pi_interoperability_layer.blast_radius import (
            BlastRadiusEngine, BlastRadiusReport, TopologyGraph, TopologyNode, TopologyEdge
        )

        engine = BlastRadiusEngine(engine_id="be1", max_graph_depth=2)
        # Baseline: flat graph (depth 0)
        base_nodes = {f"n{i}": TopologyNode(node_id=f"n{i}") for i in range(3)}
        base_edges = []
        baseline = TopologyGraph(graph_id="g_base", nodes=base_nodes, edges=base_edges)

        # Modified: chain graph (depth 9)
        mod_nodes = {f"n{i}": TopologyNode(node_id=f"n{i}") for i in range(10)}
        mod_edges = [TopologyEdge(edge_id=f"e{i}", upstream=f"n{i}", downstream=f"n{i+1}") for i in range(9)]
        modified = TopologyGraph(graph_id="g_mod", nodes=mod_nodes, edges=mod_edges)

        score = engine.compute_score(baseline, modified, "n0")
        report = BlastRadiusReport(report_id="r1", scores=[score])
        exceeded = engine.evaluate_report(report)
        assert "max_graph_depth" in exceeded


# ===========================================================================
# CTEST-13: Trust Zone Sandbox Isolation
# ===========================================================================
class TestTrustZoneSandboxIsolation:
    def test_sandbox_never_gains_authority(self):
        enforcer = TrustZoneEnforcer()
        manifest = ExtensionManifest(
            extension_id="ext-sandbox",
            package_name="pkg",
            package_version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
        )
        assert not enforcer.can_gain_governance_authority(manifest)

    def test_governed_can_gain_authority(self):
        enforcer = TrustZoneEnforcer()
        manifest = ExtensionManifest(
            extension_id="ext-gov",
            package_name="pkg",
            package_version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_zone=TrustZone.GOVERNED_EXTENSION,
        )
        assert enforcer.can_gain_governance_authority(manifest)


# ===========================================================================
# CTEST-14: Schema Compatibility
# ===========================================================================
class TestSchemaCompatibility:
    def test_same_major_compatible(self):
        reg = ContractRegistry(registry_id="cr1")
        ac = ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
        reg.register(ac)
        ok, reason = reg.compatible("c1", SchemaVersion(major=1, minor=1, patch=0))
        assert ok

    def test_major_mismatch_incompatible(self):
        reg = ContractRegistry(registry_id="cr2")
        ac = ArtifactContract(
            contract_id="c2",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
        reg.register(ac)
        ok, reason = reg.compatible("c2", SchemaVersion(major=2, minor=0, patch=0))
        assert not ok


# ===========================================================================
# CTEST-15: Console Audit Trail
# ===========================================================================
class TestConsoleAuditTrail:
    def test_audit_log_entry_is_frozen(self):
        from pi_console.schemas import AuditLogEntry

        entry = AuditLogEntry(
            tenant_id="t1",
            console_session_id="s1",
            request_id="r1",
            action="COMPOSITION_SUBMITTED",
            structured_request={"key": "value"},
        )
        with pytest.raises(ValidationError):
            entry.tenant_id = "t2"
