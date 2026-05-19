"""Semantic Diff Engine — pi-observability-diff worker.

Deterministic infrastructure diff computation between two SnapshotArtifacts.
Produces a SemanticDriftReport with strict DeltaType classification.

No LLM inference. No probabilistic reasoning. All classification is
rule-based and evidence-bound.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, OrchestrationLedger
from pi_interoperability_layer.mesh.worker_base import WorkerBase, WorkerContract
from pi_interoperability_layer.snapshot.artifacts import SnapshotArtifact


# ──────────────────────────────
#  Delta Classification
# ──────────────────────────────

class DeltaType(str, Enum):
    """Strict classification of every detected change.

    Each delta maps to exactly one DeltaType. No probabilistic classification.
    """

    # Structural deltas
    NODE_ADDED = "node_added"
    NODE_REMOVED = "node_removed"
    NODE_MODIFIED = "node_modified"
    EDGE_ADDED = "edge_added"
    EDGE_REMOVED = "edge_removed"
    EDGE_MODIFIED = "edge_modified"

    # Configuration deltas
    CONFIG_ADDED = "config_added"
    CONFIG_REMOVED = "config_removed"
    CONFIG_CHANGED = "config_changed"

    # State deltas
    STATE_CHANGED = "state_changed"
    STATE_INCREASED = "state_increased"
    STATE_DECREASED = "state_decreased"

    # Auth/Security deltas
    AUTH_ADDED = "auth_added"
    AUTH_REMOVED = "auth_removed"
    AUTH_CHANGED = "auth_changed"
    PERMISSION_ESCALATED = "permission_escalated"
    PERMISSION_DEESCALATED = "permission_deescalated"

    # Policy deltas
    POLICY_ADDED = "policy_added"
    POLICY_REMOVED = "policy_removed"
    POLICY_CHANGED = "policy_changed"

    # Topology deltas
    TOPOLOGY_EXPANDED = "topology_expanded"
    TOPOLOGY_CONTRACTED = "topology_contracted"
    TOPOLOGY_REWIRED = "topology_rewired"

    # Capability deltas
    CAPABILITY_ADDED = "capability_added"
    CAPABILITY_REMOVED = "capability_removed"
    CAPABILITY_UPDATED = "capability_updated"

    # Trust zone deltas
    TRUST_ZONE_PROMOTED = "trust_zone_promoted"
    TRUST_ZONE_DEMOTED = "trust_zone_demoted"

    # Composite/aggregate
    COMPOSITE = "composite"
    UNKNOWN = "unknown"


class SemanticDelta(BaseModel):
    """Immutable record of a single semantic change between two snapshots."""

    delta_id: str
    delta_type: DeltaType
    # Path to the changed element within the snapshot data tree
    path: str
    # Human-readable description (deterministic, not LLM-generated)
    description: str
    # Baseline value (if applicable)
    baseline_value: Optional[Any] = None
    # Modified value (if applicable)
    modified_value: Optional[Any] = None
    # Evidence for classification
    evidence: Dict[str, Any] = Field(default_factory=dict)
    # Severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
    severity: str = "INFO"
    # Deterministic hash of the delta content
    delta_hash: str = ""
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.delta_hash:
            object.__setattr__(self, "delta_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "delta_type": self.delta_type.value,
            "path": self.path,
            "description": self.description,
            "baseline_value": str(self.baseline_value) if self.baseline_value is not None else None,
            "modified_value": str(self.modified_value) if self.modified_value is not None else None,
            "evidence": self.evidence,
            "severity": self.severity,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


# ──────────────────────────────
#  Semantic Drift Report
# ──────────────────────────────

class SemanticDriftReport(BaseModel):
    """Deterministic report of all semantic differences between two snapshots.

    Immutable. Every field is derived deterministically from the inputs.
    """

    report_id: str
    baseline_snapshot_id: str
    modified_snapshot_id: str
    # All detected deltas
    deltas: List[SemanticDelta] = Field(default_factory=list)
    # Aggregate counts per delta type
    delta_counts: Dict[str, int] = Field(default_factory=dict)
    # High-severity deltas (MEDIUM, HIGH, CRITICAL)
    high_severity_deltas: List[str] = Field(default_factory=list)
    # Total drift score: bounded [0, 1], deterministic formula
    total_drift_score: float = 0.0
    # Structural drift: count of node/edge changes normalized
    structural_drift: float = 0.0
    # Semantic drift: count of config/state/auth changes normalized
    semantic_drift: float = 0.0
    # Input hash for replay verification
    input_hash: str = ""
    # Report hash for integrity
    report_hash: str = ""
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.input_hash:
            object.__setattr__(self, "input_hash", self._compute_input_hash())
        if not self.report_hash:
            object.__setattr__(self, "report_hash", self._compute_report_hash())

    def _compute_input_hash(self) -> str:
        payload = {
            "baseline": self.baseline_snapshot_id,
            "modified": self.modified_snapshot_id,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _compute_report_hash(self) -> str:
        payload = {
            "report_id": self.report_id,
            "input_hash": self.input_hash,
            "delta_count": len(self.deltas),
            "total_drift_score": self.total_drift_score,
            "structural_drift": self.structural_drift,
            "semantic_drift": self.semantic_drift,
            "delta_hashes": sorted([d.delta_hash for d in self.deltas]),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


# ──────────────────────────────
#  Diff Engine
# ──────────────────────────────

class SemanticDiffEngine:
    """Deterministic semantic diff engine.

    Computes deltas between two SnapshotArtifacts using rule-based
diff classification. Produces a SemanticDriftReport.

    NO LLM inference. NO probabilistic scoring. All logic is
    structural comparison with deterministic classification rules.
    """

    # Severity mapping by delta type
    _SEVERITY_MAP: Dict[DeltaType, str] = {
        DeltaType.PERMISSION_ESCALATED: "CRITICAL",
        DeltaType.PERMISSION_DEESCALATED: "HIGH",
        DeltaType.AUTH_ADDED: "MEDIUM",
        DeltaType.AUTH_REMOVED: "MEDIUM",
        DeltaType.AUTH_CHANGED: "HIGH",
        DeltaType.POLICY_REMOVED: "CRITICAL",
        DeltaType.POLICY_CHANGED: "HIGH",
        DeltaType.TRUST_ZONE_DEMOTED: "HIGH",
        DeltaType.NODE_REMOVED: "MEDIUM",
        DeltaType.TOPOLOGY_CONTRACTED: "MEDIUM",
    }

    def diff(
        self,
        baseline: SnapshotArtifact,
        modified: SnapshotArtifact,
    ) -> SemanticDriftReport:
        """Compute deterministic diff between two snapshots."""
        if baseline.tenant_id != modified.tenant_id:
            raise ValueError("Cannot diff snapshots from different tenants")
        if baseline.snapshot_type != modified.snapshot_type:
            raise ValueError("Cannot diff snapshots of different types")

        deltas: List[SemanticDelta] = []

        # Delegate to type-specific diff methods
        if baseline.snapshot_type.value == "topology":
            deltas = self._diff_topology(baseline, modified)
        elif baseline.snapshot_type.value == "configuration":
            deltas = self._diff_configuration(baseline, modified)
        elif baseline.snapshot_type.value == "state":
            deltas = self._diff_state(baseline, modified)
        elif baseline.snapshot_type.value == "capability_mesh":
            deltas = self._diff_capability_mesh(baseline, modified)
        elif baseline.snapshot_type.value == "trust_zone":
            deltas = self._diff_trust_zone(baseline, modified)
        elif baseline.snapshot_type.value == "policy_evaluation":
            deltas = self._diff_policy(baseline, modified)
        else:
            deltas = self._diff_generic(baseline, modified)

        # Aggregate counts
        counts: Dict[str, int] = {}
        high_severity: List[str] = []
        for d in deltas:
            counts[d.delta_type.value] = counts.get(d.delta_type.value, 0) + 1
            if d.severity in ("MEDIUM", "HIGH", "CRITICAL"):
                high_severity.append(d.delta_id)

        # Deterministic drift scores
        total_elements = max(
            len(baseline.payload.data), len(modified.payload.data), 1
        )
        structural_count = sum(
            counts.get(t, 0)
            for t in (
                "node_added", "node_removed", "node_modified",
                "edge_added", "edge_removed", "edge_modified",
                "topology_expanded", "topology_contracted", "topology_rewired",
            )
        )
        semantic_count = sum(
            counts.get(t, 0)
            for t in (
                "config_added", "config_removed", "config_changed",
                "state_changed", "auth_added", "auth_removed", "auth_changed",
                "policy_added", "policy_removed", "policy_changed",
                "capability_added", "capability_removed", "capability_updated",
            )
        )
        total_changes = len(deltas)

        structural_drift = min(structural_count / max(total_elements, 1), 1.0)
        semantic_drift = min(semantic_count / max(total_elements, 1), 1.0)
        total_drift = min(total_changes / max(total_elements * 2, 1), 1.0)

        report_id = f"drift_{baseline.snapshot_id}_{modified.snapshot_id}"

        return SemanticDriftReport(
            report_id=report_id,
            baseline_snapshot_id=baseline.snapshot_id,
            modified_snapshot_id=modified.snapshot_id,
            deltas=deltas,
            delta_counts=counts,
            high_severity_deltas=high_severity,
            total_drift_score=round(total_drift, 6),
            structural_drift=round(structural_drift, 6),
            semantic_drift=round(semantic_drift, 6),
        )

    # ------------------------------------------------------------------
    # Type-specific diff methods
    # ------------------------------------------------------------------

    def _diff_topology(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        """Diff two topology snapshots."""
        deltas: List[SemanticDelta] = []
        base_nodes = set(baseline.payload.data.get("nodes", {}).keys())
        mod_nodes = set(modified.payload.data.get("nodes", {}).keys())
        base_edges = {
            tuple(sorted((e.get("upstream", ""), e.get("downstream", ""))))
            for e in baseline.payload.data.get("edges", [])
        }
        mod_edges = {
            tuple(sorted((e.get("upstream", ""), e.get("downstream", ""))))
            for e in modified.payload.data.get("edges", [])
        }

        for node_id in mod_nodes - base_nodes:
            deltas.append(self._make_delta(
                DeltaType.NODE_ADDED, f"nodes.{node_id}",
                "Node added to topology", None, node_id,
            ))
        for node_id in base_nodes - mod_nodes:
            deltas.append(self._make_delta(
                DeltaType.NODE_REMOVED, f"nodes.{node_id}",
                "Node removed from topology", node_id, None,
            ))


        return deltas

    def _diff_configuration(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        deltas: List[SemanticDelta] = []
        base_cfg = baseline.payload.data.get("config", {})
        mod_cfg = modified.payload.data.get("config", {})
        all_keys = set(base_cfg.keys()) | set(mod_cfg.keys())
        for key in sorted(all_keys):
            if key in mod_cfg and key not in base_cfg:
                deltas.append(self._make_delta(
                    DeltaType.CONFIG_ADDED, f"config.{key}",
                    f"Configuration key '{key}' added", None, mod_cfg[key],
                ))
            elif key in base_cfg and key not in mod_cfg:
                deltas.append(self._make_delta(
                    DeltaType.CONFIG_REMOVED, f"config.{key}",
                    f"Configuration key '{key}' removed", base_cfg[key], None,
                ))
            elif base_cfg.get(key) != mod_cfg.get(key):
                deltas.append(self._make_delta(
                    DeltaType.CONFIG_CHANGED, f"config.{key}",
                    f"Configuration key '{key}' changed", base_cfg[key], mod_cfg[key],
                ))
        return deltas

    def _diff_state(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        deltas: List[SemanticDelta] = []
        base_state = baseline.payload.data.get("state", {})
        mod_state = modified.payload.data.get("state", {})
        for key in sorted(set(base_state.keys()) | set(mod_state.keys())):
            b_val = base_state.get(key)
            m_val = mod_state.get(key)
            if b_val != m_val:
                dt = DeltaType.STATE_CHANGED
                # Numeric comparison for directional classification
                try:
                    if isinstance(b_val, (int, float)) and isinstance(m_val, (int, float)):
                        if m_val > b_val:
                            dt = DeltaType.STATE_INCREASED
                        elif m_val < b_val:
                            dt = DeltaType.STATE_DECREASED
                except (TypeError, ValueError):
                    pass
                deltas.append(self._make_delta(
                    dt, f"state.{key}",
                    f"State '{key}' changed", b_val, m_val,
                ))
        return deltas

    def _diff_capability_mesh(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        deltas: List[SemanticDelta] = []
        base_caps = set(baseline.payload.data.get("capabilities", []))
        mod_caps = set(modified.payload.data.get("capabilities", []))
        for cap in sorted(mod_caps - base_caps):
            deltas.append(self._make_delta(
                DeltaType.CAPABILITY_ADDED, f"capabilities.{cap}",
                f"Capability '{cap}' added", None, cap,
            ))
        for cap in sorted(base_caps - mod_caps):
            deltas.append(self._make_delta(
                DeltaType.CAPABILITY_REMOVED, f"capabilities.{cap}",
                f"Capability '{cap}' removed", cap, None,
            ))
        return deltas

    def _diff_trust_zone(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        deltas: List[SemanticDelta] = []
        base_zones = baseline.payload.data.get("trust_zones", {})
        mod_zones = modified.payload.data.get("trust_zones", {})
        for entity_id in sorted(set(base_zones.keys()) | set(mod_zones.keys())):
            b_zone = base_zones.get(entity_id)
            m_zone = mod_zones.get(entity_id)
            if b_zone != m_zone:
                if b_zone is None:
                    deltas.append(self._make_delta(
                        DeltaType.NODE_ADDED, f"trust_zones.{entity_id}",
                        f"Entity '{entity_id}' added to trust zone map", None, m_zone,
                    ))
                elif m_zone is None:
                    deltas.append(self._make_delta(
                        DeltaType.NODE_REMOVED, f"trust_zones.{entity_id}",
                        f"Entity '{entity_id}' removed from trust zone map", b_zone, None,
                    ))
                else:
                    # Determine promotion/demotion
                    zone_rank = {"SANDBOX_EXPERIMENTAL": 0, "GOVERNED_EXTENSION": 1, "CORE_TRUSTED": 2}
                    b_rank = zone_rank.get(b_zone, -1)
                    m_rank = zone_rank.get(m_zone, -1)
                    if m_rank > b_rank:
                        dt = DeltaType.TRUST_ZONE_PROMOTED
                    else:
                        dt = DeltaType.TRUST_ZONE_DEMOTED
                    deltas.append(self._make_delta(
                        dt, f"trust_zones.{entity_id}",
                        f"Entity '{entity_id}' trust zone changed from {b_zone} to {m_zone}",
                        b_zone, m_zone,
                    ))
        return deltas

    def _diff_policy(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        deltas: List[SemanticDelta] = []
        base_pol = baseline.payload.data.get("policies", {})
        mod_pol = modified.payload.data.get("policies", {})
        for pid in sorted(set(base_pol.keys()) | set(mod_pol.keys())):
            b = base_pol.get(pid)
            m = mod_pol.get(pid)
            if b is None and m is not None:
                deltas.append(self._make_delta(
                    DeltaType.POLICY_ADDED, f"policies.{pid}",
                    f"Policy '{pid}' added", None, m,
                ))
            elif b is not None and m is None:
                deltas.append(self._make_delta(
                    DeltaType.POLICY_REMOVED, f"policies.{pid}",
                    f"Policy '{pid}' removed", b, None,
                ))
            elif b != m:
                deltas.append(self._make_delta(
                    DeltaType.POLICY_CHANGED, f"policies.{pid}",
                    f"Policy '{pid}' modified", b, m,
                ))
        return deltas

    def _diff_generic(
        self, baseline: SnapshotArtifact, modified: SnapshotArtifact
    ) -> List[SemanticDelta]:
        """Fallback generic diff: compare top-level keys."""
        deltas: List[SemanticDelta] = []
        base_keys = set(baseline.payload.data.keys())
        mod_keys = set(modified.payload.data.keys())
        for key in sorted(mod_keys - base_keys):
            deltas.append(self._make_delta(
                DeltaType.COMPOSITE, key,
                f"Key '{key}' added", None, modified.payload.data[key],
            ))
        for key in sorted(base_keys - mod_keys):
            deltas.append(self._make_delta(
                DeltaType.COMPOSITE, key,
                f"Key '{key}' removed", baseline.payload.data[key], None,
            ))
        for key in sorted(base_keys & mod_keys):
            if baseline.payload.data[key] != modified.payload.data[key]:
                deltas.append(self._make_delta(
                    DeltaType.COMPOSITE, key,
                    f"Key '{key}' changed", baseline.payload.data[key], modified.payload.data[key],
                ))
        return deltas

    def _make_delta(
        self,
        delta_type: DeltaType,
        path: str,
        description: str,
        baseline_value: Optional[Any],
        modified_value: Optional[Any],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> SemanticDelta:
        severity = self._SEVERITY_MAP.get(delta_type, "INFO")
        return SemanticDelta(
            delta_id=f"delta_{delta_type.value}_{hashlib.sha256(path.encode()).hexdigest()[:16]}",
            delta_type=delta_type,
            path=path,
            description=description,
            baseline_value=baseline_value,
            modified_value=modified_value,
            evidence=evidence or {},
            severity=severity,
        )


# ──────────────────────────────
#  Worker
# ──────────────────────────────

class PiObservabilityDiffWorker(WorkerBase):
    """Observability diff worker: computes SemanticDriftReport from two snapshots.

    Input slots:
      - baseline_snapshot: SnapshotArtifact (artifact_type: Snapshot)
      - modified_snapshot: SnapshotArtifact (artifact_type: Snapshot)

    Output slots:
      - drift_report: SemanticDriftReport (artifact_type: SemanticDriftReport)
    """

    def __init__(
        self,
        worker_id: str,
        bus: ArtifactBus,
        ledger: OrchestrationLedger,
    ) -> None:
        contract = WorkerContract(
            worker_class="PiObservabilityDiffWorker",
            required_input_artifact_types=["SnapshotArtifact", "SnapshotArtifact"],
            produced_output_artifact_types=["SemanticDriftReport"],
            max_execution_ms=60000.0,
            max_memory_mb=256.0,
            max_input_slots=2,
            max_output_slots=1,
            deterministic=True,
        )
        super().__init__(worker_id, contract, bus, ledger)
        self._engine = SemanticDiffEngine()

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        if len(input_slot_ids) != 2:
            raise ValueError(f"Expected 2 input slots, got {len(input_slot_ids)}")

        baseline_slot = self.bus.read(input_slot_ids[0])
        modified_slot = self.bus.read(input_slot_ids[1])
        if baseline_slot is None or modified_slot is None:
            raise ValueError("Missing input snapshot slots")

        baseline = SnapshotArtifact(**baseline_slot.payload)
        modified = SnapshotArtifact(**modified_slot.payload)

        report = self._engine.diff(baseline, modified)

        output_slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SemanticDriftReport",
            payload=report.model_dump(mode="json"),
        )
        return [self.bus.write(output_slot)]
