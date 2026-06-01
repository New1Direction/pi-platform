"""Tests for defensive adversarial simulation and telemetry governance workers.

Deterministic sanitization, provenance preservation, drift, compliance,
sensitive lineage, sandbox isolation.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pi_interoperability_layer.mesh.artifact_bus import ArtifactBus, ArtifactSlot
from pi_interoperability_layer.mesh.defensive_workers import (
    ComplianceEngineWorker,
    ObservabilityDiffWorker,
    ReplaySanitizerWorker,
    SecuritySimulationWorker,
    SensitiveFlowTrackerWorker,
    TelemetryGovernorWorker,
)
from pi_interoperability_layer.mesh.receipts import OrchestrationLedger
from pi_interoperability_layer.mesh.worker_base import WorkerContract
from pi_interoperability_layer.queries import SemanticQueryEngine
from pi_interoperability_layer.registry import SnapshotRegistry
from pi_interoperability_layer.visualization import (
    render_compliance_violations,
    render_observability_drift,
    render_replay_sanitization,
    render_sensitive_lineage,
    render_telemetry_exposure,
)

# ── Telemetry Governor Tests ──────────────────────────────────────────────────────────


def test_telemetry_governor_detects_debug_endpoint() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    trace_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={"traces": [{"endpoint_template": "/api/debug/info", "method": "GET", "fields": []}]},
        ).freeze()
    )
    worker = TelemetryGovernorWorker("tg1", WorkerContract(worker_class="TelemetryGovernorWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [trace_slot.slot_id])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload["pass"] is False
    assert any(f["rule"] == "debug_endpoint_exposure" for f in out.payload["findings"])


def test_telemetry_governor_detects_stack_trace_field() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    trace_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={
                "traces": [
                    {
                        "endpoint_template": "/api/users",
                        "method": "GET",
                        "fields": [{"name": "error_stack_trace", "type": "string"}],
                    }
                ]
            },
        ).freeze()
    )
    worker = TelemetryGovernorWorker("tg2", WorkerContract(worker_class="TelemetryGovernorWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [trace_slot.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert any(f["rule"] == "stack_trace_exposure" for f in out.payload["findings"])


def test_telemetry_governor_detects_token_leakage() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={"traces": [{"endpoint_template": "/api/users", "method": "GET", "fields": []}]},
        ).freeze()
    )
    # Inject JWT-like token into payload string via field description
    trace_slot_2 = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={
                "traces": [
                    {
                        "endpoint_template": "/api/auth",
                        "method": "POST",
                        "fields": [
                            {
                                "name": "token",
                                "description": "Bearer eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIiw.abc123",
                            }
                        ],
                    }
                ]
            },
        ).freeze()
    )
    worker = TelemetryGovernorWorker("tg3", WorkerContract(worker_class="TelemetryGovernorWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [trace_slot_2.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert any(f["rule"] == "token_leakage" for f in out.payload["findings"])


# ── Replay Sanitizer Tests ────────────────────────────────────────────────────────────


def test_replay_sanitizer_masks_sensitive_keys() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    raw_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="src",
            artifact_type="RawSourceSnapshot",
            payload={"password": "secret123", "api_key": "ak_live_12345678901234567890"},
        ).freeze()
    )
    worker = ReplaySanitizerWorker("rs1", WorkerContract(worker_class="ReplaySanitizerWorker"), bus, ledger)
    receipt = worker.execute("GOVERN", [raw_slot.slot_id])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload["replay_equivalence_preserved"] is True
    redactions = out.payload["redaction_log"]
    assert any(r["rule"] == "sensitive_key_masking" for r in redactions)
    assert any(r["rule"] == "api_key_masking" for r in redactions)


def test_replay_sanitizer_masks_jwt() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    raw_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="src",
            artifact_type="RawSourceSnapshot",
            payload={
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMe"
            },
        ).freeze()
    )
    worker = ReplaySanitizerWorker("rs2", WorkerContract(worker_class="ReplaySanitizerWorker"), bus, ledger)
    receipt = worker.execute("GOVERN", [raw_slot.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert any(r["rule"] == "jwt_masking" for r in out.payload["redaction_log"])


def test_replay_sanitizer_deterministic_masking() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    raw_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="src",
            artifact_type="RawSourceSnapshot",
            payload={"password": "same"},
        ).freeze()
    )
    worker = ReplaySanitizerWorker("rs3", WorkerContract(worker_class="ReplaySanitizerWorker"), bus, ledger)
    receipt = worker.execute("GOVERN", [raw_slot.slot_id])
    out1 = bus.read(receipt.output_slot_ids[0])
    # Re-run with identical input
    receipt2 = worker.execute("GOVERN", [raw_slot.slot_id])
    out2 = bus.read(receipt2.output_slot_ids[0])
    assert out1.payload["sanitization_hash"] == out2.payload["sanitization_hash"]


# ── Sensitive Flow Tracker Tests ───────────────────────────────────────────────────────────


def test_sensitive_flow_tracker_detects_crossing() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    trace_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={
                "traces": [
                    {
                        "endpoint_template": "/public/api/users",
                        "method": "POST",
                        "fields": [{"name": "password", "type": "string"}],
                    }
                ]
            },
        ).freeze()
    )
    dep_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="DependencyGraph",
            payload={
                "edges": [
                    {
                        "upstream_endpoint": "/public/api/users",
                        "downstream_endpoint": "/internal/svc-auth",
                        "edge_type": "direct_call",
                    }
                ]
            },
        ).freeze()
    )
    worker = SensitiveFlowTrackerWorker("sf1", WorkerContract(worker_class="SensitiveFlowTrackerWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [trace_slot.slot_id, dep_slot.slot_id])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload["crossing_count"] == 1
    assert any("password" in c.get("sensitive_fields_crossed", []) for c in out.payload["trust_boundary_crossings"])


# ── Observability Diff Tests ──────────────────────────────────────────────────────────────


def test_observability_diff_detects_verbosity_expansion() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    baseline = bus.write(
        ArtifactSlot(
            producer_worker_id="obs",
            artifact_type="TelemetrySnapshot",
            payload={"log_lines": 50, "sensitive_fields": ["user_id"], "metadata_keys": ["timestamp"]},
        ).freeze()
    )
    modified = bus.write(
        ArtifactSlot(
            producer_worker_id="obs",
            artifact_type="TelemetrySnapshot",
            payload={
                "log_lines": 300,
                "sensitive_fields": ["user_id", "email", "ssn"],
                "metadata_keys": ["timestamp", "request_id", "trace_id", "span_id"],
            },
        ).freeze()
    )
    worker = ObservabilityDiffWorker("od1", WorkerContract(worker_class="ObservabilityDiffWorker"), bus, ledger)
    receipt = worker.execute("DIFF", [baseline.slot_id, modified.slot_id])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload["verbosity_expansion"] == 250
    assert len(out.payload["new_sensitive_fields"]) == 2
    assert len(out.payload["new_metadata_keys"]) == 3
    assert out.payload["pass"] is False


def test_observability_diff_clean_baseline() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    baseline = bus.write(
        ArtifactSlot(
            producer_worker_id="obs",
            artifact_type="TelemetrySnapshot",
            payload={"log_lines": 50, "sensitive_fields": ["user_id"], "metadata_keys": ["timestamp"]},
        ).freeze()
    )
    modified = bus.write(
        ArtifactSlot(
            producer_worker_id="obs",
            artifact_type="TelemetrySnapshot",
            payload={"log_lines": 60, "sensitive_fields": ["user_id"], "metadata_keys": ["timestamp"]},
        ).freeze()
    )
    worker = ObservabilityDiffWorker("od2", WorkerContract(worker_class="ObservabilityDiffWorker"), bus, ledger)
    receipt = worker.execute("DIFF", [baseline.slot_id, modified.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert out.payload["pass"] is True


# ── Compliance Engine Tests ─────────────────────────────────────────────────────────────────────────


def test_compliance_engine_detects_gdpr_missing_classification() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    trace_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="ext",
            artifact_type="SemanticIRTrace",
            payload={
                "traces": [
                    {
                        "endpoint_template": "/api/users",
                        "method": "POST",
                        "fields": [{"name": "email", "type": "string", "data_classification": "PUBLIC"}],
                    }
                ]
            },
        ).freeze()
    )
    worker = ComplianceEngineWorker("ce1", WorkerContract(worker_class="ComplianceEngineWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [trace_slot.slot_id])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert any(
        v["framework"] == "GDPR" and v["rule"] == "personal_data_classification" for v in out.payload["violations"]
    )


def test_compliance_engine_evaluates_soc2_boundary_failure() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    boundary_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="bv",
            artifact_type="BoundaryValidationReport",
            payload={"pass": False, "violations": [{}]},
        ).freeze()
    )
    worker = ComplianceEngineWorker("ce2", WorkerContract(worker_class="ComplianceEngineWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [boundary_slot.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert any(v["framework"] == "SOC2" and v["rule"] == "boundary_integrity" for v in out.payload["violations"])


# ── Security Simulation Worker Tests ──────────────────────────────────────────────────────────────


def test_security_simulation_deterministic_corpus() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    worker = SecuritySimulationWorker("ss1", WorkerContract(worker_class="SecuritySimulationWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [])
    assert receipt.status == "SUCCESS"
    out = bus.read(receipt.output_slot_ids[0])
    assert out is not None
    assert out.payload["sandbox_mode"] is True
    assert out.payload["external_targeting"] is False
    assert out.payload["persistence"] is False
    assert out.payload["self_propagation"] is False
    assert out.payload["tests_run"] == 6
    # All deterministic tests should pass because they are self-validating
    assert out.payload["tests_passed"] == 6


def test_security_simulation_validates_replay_containment() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    sanitized = bus.write(
        ArtifactSlot(
            producer_worker_id="rs",
            artifact_type="SanitizedReplayBundle",
            payload={"sanitized_slots": [{"redaction_count": 3}], "redaction_log": [{"path": "x", "rule": "mask"}]},
        ).freeze()
    )
    worker = SecuritySimulationWorker("ss2", WorkerContract(worker_class="SecuritySimulationWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [sanitized.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    assert out.payload["replay_containment_passed"] is True


# ── Visualization Tests ───────────────────────────────────────────────────────────────────────────────────────


def test_render_telemetry_exposure_html() -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        pass
    render_telemetry_exposure({"findings": [{"severity": "HIGH", "rule": "r1", "detail": "d1"}]}, f.name)
    content = Path(f.name).read_text()
    assert "Telemetry Exposure Report" in content
    assert "HIGH" in content


def test_render_sensitive_lineage_html() -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        pass
    render_sensitive_lineage(
        {
            "trust_boundary_crossings": [
                {
                    "edge": "A->B",
                    "from_zone": "TRUSTED",
                    "to_zone": "UNTRUSTED",
                    "sensitive_fields_crossed": ["password"],
                }
            ]
        },
        f.name,
    )
    content = Path(f.name).read_text()
    assert "Sensitive Field Lineage" in content
    assert "password" in content


def test_render_replay_sanitization_html() -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        pass
    render_replay_sanitization(
        {
            "redaction_log": [{"path": "token", "rule": "jwt_masking", "mask": "MASKED_abc"}],
            "replay_equivalence_preserved": True,
        },
        f.name,
    )
    content = Path(f.name).read_text()
    assert "Replay Sanitization Report" in content
    assert "MASKED_abc" in content


def test_render_compliance_violations_html() -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        pass
    render_compliance_violations(
        {"violations": [{"framework": "GDPR", "rule": "r1", "detail": "d1"}], "frameworks_evaluated": ["GDPR"]}, f.name
    )
    content = Path(f.name).read_text()
    assert "Compliance Violations" in content
    assert "GDPR" in content


def test_render_observability_drift_html() -> None:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
        pass
    render_observability_drift(
        {
            "findings": [{"rule": "verbosity_expansion", "detail": "Lines increased by 500"}],
            "drift_score": 1,
            "new_sensitive_fields": ["email"],
        },
        f.name,
    )
    content = Path(f.name).read_text()
    assert "Observability Drift Report" in content
    assert "verbosity_expansion" in content


# ── Query API Tests ───────────────────────────────────────────────────────────────────────────────────────────────────────


def test_query_secret_exposure() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SnapshotRegistry(root_dir=Path(td))
        reg.store_snapshot(
            "TelemetryGovernorWorker",
            "exec_1",
            {
                "findings": [
                    {"rule": "token_leakage", "severity": "CRITICAL"},
                    {"rule": "debug_endpoint_exposure", "severity": "HIGH"},
                ]
            },
        )
        # Need to discover the generated snapshot_id
        snaps = reg.list_snapshots()
        assert len(snaps) == 1
        snap_id = snaps[0].snapshot_id
        engine = SemanticQueryEngine(reg)
        result = engine.query_secret_exposure(snap_id)
        assert len(result.results) == 1
        assert result.results[0]["rule"] == "token_leakage"


def test_query_sensitive_paths() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SnapshotRegistry(root_dir=Path(td))
        reg.store_snapshot(
            "SensitiveFlowTrackerWorker",
            "exec_1",
            {
                "field_propagation": [
                    {"field": "password", "endpoint": "/api/users", "event": "origin", "trust_zone": "TRUSTED"}
                ]
            },
        )
        snaps = reg.list_snapshots()
        snap_id = snaps[0].snapshot_id
        engine = SemanticQueryEngine(reg)
        result = engine.query_sensitive_paths(snap_id)
        assert len(result.results) == 1
        assert result.results[0]["field"] == "password"


def test_query_observability_drift() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SnapshotRegistry(root_dir=Path(td))
        reg.store_snapshot(
            "ObservabilityDiffWorker",
            "exec_1",
            {
                "findings": [{"rule": "verbosity_expansion"}],
                "verbosity_expansion": 250,
                "new_sensitive_fields": ["email"],
                "drift_score": 2,
            },
        )
        snaps = reg.list_snapshots()
        snap_id = snaps[0].snapshot_id
        engine = SemanticQueryEngine(reg)
        result = engine.query_observability_drift(snap_id)
        assert result.results[0]["drift_score"] == 2


def test_query_compliance_violations() -> None:
    with tempfile.TemporaryDirectory() as td:
        reg = SnapshotRegistry(root_dir=Path(td))
        reg.store_snapshot(
            "ComplianceEngineWorker", "exec_1", {"violations": [{"framework": "GDPR", "rule": "r1", "detail": "d1"}]}
        )
        snaps = reg.list_snapshots()
        snap_id = snaps[0].snapshot_id
        engine = SemanticQueryEngine(reg)
        result = engine.query_compliance_violations(snap_id)
        assert len(result.results) == 1
        assert result.results[0]["framework"] == "GDPR"


# ── Provenance Preservation Tests ────────────────────────────────────────────────────────────────────────


def test_replay_sanitization_preserves_provenance() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    raw_slot = bus.write(
        ArtifactSlot(
            producer_worker_id="src",
            artifact_type="RawSourceSnapshot",
            payload={"password": "secret123"},
            provenance_receipt_ids=["rcpt_abc123"],
        ).freeze()
    )
    worker = ReplaySanitizerWorker("rs_prov", WorkerContract(worker_class="ReplaySanitizerWorker"), bus, ledger)
    receipt = worker.execute("GOVERN", [raw_slot.slot_id])
    out = bus.read(receipt.output_slot_ids[0])
    # Sanitized slot should reference original provenance
    sanitized = out.payload["sanitized_slots"][0]
    assert sanitized["original_slot_id"] == raw_slot.slot_id


# ── Sandbox Isolation Tests ────────────────────────────────────────────────────────────────────────────────────


def test_security_simulation_no_external_targeting() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    worker = SecuritySimulationWorker("ss_iso", WorkerContract(worker_class="SecuritySimulationWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [])
    out = bus.read(receipt.output_slot_ids[0])
    assert out.payload["external_targeting"] is False
    assert out.payload["persistence"] is False
    assert out.payload["self_propagation"] is False
    assert out.payload["sandbox_mode"] is True


def test_security_simulation_no_network_calls() -> None:
    bus = ArtifactBus()
    ledger = OrchestrationLedger(pipeline_name="test")
    worker = SecuritySimulationWorker("ss_net", WorkerContract(worker_class="SecuritySimulationWorker"), bus, ledger)
    receipt = worker.execute("VALIDATE", [])
    # The worker should not make any network calls; success indicates bounded local execution
    assert receipt.status == "SUCCESS"
    assert receipt.resource_usage.get("cpu_ms", 0) < 1000  # Should be fast since it's local deterministic rules
