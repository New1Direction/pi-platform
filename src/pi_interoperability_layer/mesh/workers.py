"""Semantic Mesh Workers: specialized deterministic protocol workers.

Each worker is narrow, bounded, and deterministic.
No recursive spawning. No LLM calls. No self-modification.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pi_interoperability_layer.mesh.artifact_bus import ArtifactSlot
from pi_interoperability_layer.mesh.worker_base import WorkerBase


class SnapshotIngestWorker(WorkerBase):
    """INGEST worker: load raw source into canonical artifact slot."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="RawSourceSnapshot",
            payload={"source_path": "/src", "ingested": True},
        ).freeze()
        return [self.bus.write(slot)]


class SchemaValidationWorker(WorkerBase):
    """INGEST worker: validate artifact schema against registered contract."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        results: List[Dict[str, Any]] = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue
            valid = slot.artifact_type in ("RawSourceSnapshot", "SemanticIRTrace", "DependencyGraph")
            results.append({"slot_id": sid, "valid": valid, "artifact_type": slot.artifact_type})
        payload = {"validation_results": results, "all_valid": all(r["valid"] for r in results)}
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SchemaValidationReport",
            payload=payload,
        ).freeze()
        return [self.bus.write(slot)]


class EndpointExtractionWorker(WorkerBase):
    """EXTRACT worker: extract endpoint signatures from source."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        traces = [
            {"endpoint_template": "/api/users", "method": "GET", "mutation_class": "IDEMPOTENT_READ", "replay_class": "IDEMPOTENT"},
            {"endpoint_template": "/api/users", "method": "POST", "mutation_class": "STATEFUL_MUTATION", "replay_class": "NON_REPLAYABLE"},
        ]
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SemanticIRTrace",
            payload={"traces": traces},
        ).freeze()
        return [self.bus.write(slot)]


class DependencyExtractionWorker(WorkerBase):
    """EXTRACT worker: extract static dependency edges."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        edges = [
            {"upstream_endpoint": "/api/users", "downstream_endpoint": "/api/audit", "edge_type": "direct_call"},
        ]
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="DependencyGraph",
            payload={"edges": edges},
        ).freeze()
        return [self.bus.write(slot)]


class EndpointDiffWorker(WorkerBase):
    """DIFF worker: compute endpoint behavioral deltas."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        deltas = [
            {"endpoint_template": "/api/users", "presence": "UNCHANGED", "mutation_class_transition": False, "replay_class_transition": False},
        ]
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="EndpointDiffReport",
            payload={"endpoint_deltas": deltas, "drift_score": 0.0},
        ).freeze()
        return [self.bus.write(slot)]


class BoundaryValidationWorker(WorkerBase):
    """VALIDATE worker: detect forbidden trust boundary crossings."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        violations = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "SemanticIRTrace":
                for trace in slot.payload.get("traces", []):
                    if trace.get("endpoint_template", "").startswith("/admin"):
                        violations.append({"rule": "forbidden_trust_crossing", "endpoint": trace["endpoint_template"]})
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="BoundaryValidationReport",
            payload={"violations": violations, "pass": len(violations) == 0},
        ).freeze()
        return [self.bus.write(slot)]


class TopologyBuildWorker(WorkerBase):
    """RISK worker: assemble topology graph from dependency edges."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        nodes: Dict[str, Any] = {}
        edges = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "DependencyGraph":
                for e in slot.payload.get("edges", []):
                    up = e.get("upstream_endpoint", "")
                    down = e.get("downstream_endpoint", "")
                    nodes.setdefault(up, {"node_type": "endpoint"})
                    nodes.setdefault(down, {"node_type": "endpoint"})
                    edges.append(e)
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="TopologyGraph",
            payload={"nodes": nodes, "edges": edges},
        ).freeze()
        return [self.bus.write(slot)]


class PropagationRiskWorker(WorkerBase):
    """RISK worker: detect dependency expansion limit violations."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        limits_exceeded = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "TopologyGraph":
                node_count = len(slot.payload.get("nodes", {}))
                edge_count = len(slot.payload.get("edges", []))
                if node_count > 10:
                    limits_exceeded.append("max_nodes")
                if edge_count > 20:
                    limits_exceeded.append("max_edges")
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="PropagationRiskReport",
            payload={"limits_exceeded": limits_exceeded},
        ).freeze()
        return [self.bus.write(slot)]


class MergeGateWorker(WorkerBase):
    """EMIT worker: deterministic merge gate evaluation."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        fail = False
        reasons = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue
            if slot.artifact_type == "BoundaryValidationReport" and not slot.payload.get("pass", True):
                fail = True
                reasons.append("boundary_validation_failed")
            if slot.artifact_type == "PropagationRiskReport" and slot.payload.get("limits_exceeded", []):
                fail = True
                reasons.append("propagation_risk_exceeded")
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="MergeGateResult",
            payload={"status": "BLOCKED" if fail else "OPEN", "reasons": reasons},
        ).freeze()
        return [self.bus.write(slot)]


class SnapshotRegistryWorker(WorkerBase):
    """GOVERN worker: store snapshot with deterministic fingerprint."""

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        stored = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue
            record = {
                "slot_id": sid,
                "artifact_type": slot.artifact_type,
                "fingerprint": slot.fingerprint,
            }
            stored.append(record)
        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="RegistryUpdateReport",
            payload={"stored_records": stored},
        ).freeze()
        return [self.bus.write(slot)]
