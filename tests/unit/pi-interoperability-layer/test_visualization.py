"""Tests for governance visualization layer."""

from __future__ import annotations

from pathlib import Path
import tempfile
import json

from pi_interoperability_layer.visualization import (
    render_validation_html,
    render_diff_heatmap,
    render_topology_graph,
    render_governance_dashboard,
)


def test_render_validation_html() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        report = {
            "status": "FAIL",
            "generated_at": "2024-01-01T00:00:00Z",
            "violations": [
                {"pass_name": "boundary", "rule": "forbidden_crossing", "severity": "CRITICAL", "context": {"endpoint": "/api/admin"}},
            ],
        }
        in_path = Path(tmp) / "validation.json"
        out_path = Path(tmp) / "validation.html"
        with open(in_path, "w") as f:
            json.dump(report, f)
        render_validation_html(in_path, out_path)
        assert out_path.exists()
        content = out_path.read_text()
        assert "FAIL" in content
        assert "forbidden_crossing" in content


def test_render_diff_heatmap() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        diff = {
            "drift_score": 0.75,
            "structural_delta_score": 0.5,
            "semantic_delta_score": 0.25,
            "endpoint_deltas": [
                {"endpoint_template": "/api/users", "presence": "ADDED", "mutation_class_transition": True, "replay_class_transition": False},
            ],
        }
        out_path = Path(tmp) / "diff.html"
        render_diff_heatmap(diff, out_path)
        assert out_path.exists()
        content = out_path.read_text()
        assert "0.7500" in content or "0.75" in content


def test_render_topology_graph() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        topo = {
            "nodes": {
                "n1": {"node_type": "endpoint"},
                "n2": {"node_type": "service"},
            },
            "edges": [
                {"upstream": "n1", "downstream": "n2", "edge_type": "direct_call"},
            ],
        }
        out_path = Path(tmp) / "topology.json"
        render_topology_graph(topo, out_path)
        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1


def test_render_governance_dashboard() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "dashboard.html"
        validation = {"status": "PASS"}
        diff = {"drift_score": 0.1}
        risk = {"limits_exceeded": []}
        render_governance_dashboard(validation, diff, risk, out_path)
        assert out_path.exists()
        content = out_path.read_text()
        assert "PASS" in content
        assert "WITHIN LIMITS" in content


def test_render_governance_dashboard_fail() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "dashboard.html"
        validation = {"status": "FAIL"}
        diff = {"drift_score": 0.8}
        risk = {"limits_exceeded": ["max_depth"]}
        render_governance_dashboard(validation, diff, risk, out_path)
        content = out_path.read_text()
        assert "FAIL" in content
        assert "LIMITS EXCEEDED" in content
