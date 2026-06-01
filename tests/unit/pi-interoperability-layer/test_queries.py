"""Tests for semantic query engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pi_interoperability_layer.queries import SemanticQueryEngine
from pi_interoperability_layer.registry import SnapshotRegistry


def _make_registry() -> tuple[SnapshotRegistry, str]:
    tmp = tempfile.mkdtemp()
    reg = SnapshotRegistry(Path(tmp))
    payload = {
        "traces": [
            {
                "endpoint_template": "/api/users",
                "method": "GET",
                "mutation_class": "IDEMPOTENT_READ",
                "replay_class": "IDEMPOTENT",
            },
            {
                "endpoint_template": "/api/users",
                "method": "POST",
                "mutation_class": "STATEFUL_MUTATION",
                "replay_class": "NON_REPLAYABLE",
            },
        ],
        "auth": [
            {"invariant_id": "auth1", "invariant_type": "bearer", "affected_endpoints": ["/api/users"]},
        ],
        "graph": {
            "edges": [
                {"upstream_endpoint": "/api/users", "downstream_endpoint": "/api/audit"},
            ],
        },
    }
    record = reg.store_snapshot("recon", "exec_1", payload)
    return reg, record.metadata.snapshot_id


def test_query_endpoints_by_mutation_class() -> None:
    reg, snap_id = _make_registry()
    engine = SemanticQueryEngine(reg)
    result = engine.query_endpoints_by_mutation_class(snap_id, "STATEFUL_MUTATION")
    assert len(result.results) == 1
    assert result.results[0]["endpoint"] == "/api/users"
    assert result.results[0]["method"] == "POST"


def test_query_replay_surface() -> None:
    reg, snap_id = _make_registry()
    engine = SemanticQueryEngine(reg)
    result = engine.query_replay_surface(snap_id)
    assert len(result.results) == 2


def test_query_auth_boundaries() -> None:
    reg, snap_id = _make_registry()
    engine = SemanticQueryEngine(reg)
    result = engine.query_auth_boundaries(snap_id)
    assert len(result.results) == 1
    assert result.results[0]["invariant_id"] == "auth1"


def test_query_topology_lineage() -> None:
    reg, snap_id = _make_registry()
    engine = SemanticQueryEngine(reg)
    result = engine.query_topology_lineage(snap_id, "/api/users")
    assert len(result.results) == 1
    assert result.results[0]["downstream"] == ["/api/audit"]


def test_query_drift_summary_missing_bundle() -> None:
    reg, _ = _make_registry()
    engine = SemanticQueryEngine(reg)
    result = engine.query_drift_summary("nonexistent")
    assert result.results == []
