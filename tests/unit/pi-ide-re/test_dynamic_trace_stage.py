"""
Tests for the Frida DynamicTraceStage.

Capture (live) needs frida + a running process and is NOT exercised here.
Ingest is deterministic and fully tested: saved trace JSON -> content-addressed
DynamicTrace nodes grouped by hook. Re-ingest is stable; volatile pid/time do
not change identity. Missing frida degrades to a clear StageError.
"""

from __future__ import annotations

import json

import pytest

from pi_ide_re.stages import dynamic_trace as dt
from pi_ide_re.stages.base import StageError

SAMPLE_CAPTURE = {
    "target": "Antigravity Helper",
    "pid": 4321,
    "captured_at": "2026-06-01T10:00:00Z",
    "script": "objc-msgsend-filter",
    "messages": [
        {"type": "send", "payload": {"hook": "objc_msgSend", "selector": "toolCall:"}},
        {"type": "send", "payload": {"hook": "objc_msgSend", "selector": "agentStep:"}},
        {"type": "send", "payload": {"hook": "objc_msgSend", "selector": "toolCall:"}},  # dup
        {"type": "send", "payload": {"hook": "send", "preview": "POST /v1/generate"}},
        {"type": "error", "description": "boom"},
    ],
}


class TestIngest:
    def test_groups_messages_by_hook_into_dynamic_traces(self):
        stage = dt.DynamicTraceStage()
        result = stage.ingest(SAMPLE_CAPTURE)
        trace_nodes = [n for n in result.nodes if n.type == "dynamic-trace"]
        hooks = {n.title.split(" :: ")[-1] for n in trace_nodes}
        assert "objc_msgSend" in hooks
        assert "send" in hooks
        # the objc_msgSend trace deduped toolCall:
        objc = next(n for n in trace_nodes if n.title.endswith("objc_msgSend"))
        payload = json.loads(objc.content)
        assert sorted(payload["findings"]) == ["agentStep:", "toolCall:"]

    def test_reingest_is_deterministic(self):
        stage = dt.DynamicTraceStage()
        ids_a = sorted(n.id for n in stage.ingest(SAMPLE_CAPTURE).nodes)
        ids_b = sorted(n.id for n in stage.ingest(SAMPLE_CAPTURE).nodes)
        assert ids_a == ids_b

    def test_volatile_pid_and_time_do_not_change_node_ids(self):
        stage = dt.DynamicTraceStage()
        a = sorted(n.id for n in stage.ingest(SAMPLE_CAPTURE).nodes)
        variant = dict(SAMPLE_CAPTURE, pid=9999, captured_at="2027-01-01T00:00:00Z")
        b = sorted(n.id for n in stage.ingest(variant).nodes)
        assert a == b

    def test_errors_recorded_in_summary_not_as_nodes(self):
        stage = dt.DynamicTraceStage()
        result = stage.ingest(SAMPLE_CAPTURE)
        assert result.summary["errors"] == 1
        assert all(n.type == "dynamic-trace" or n.type == "entity" for n in result.nodes)

    def test_links_traces_to_target_entity(self):
        stage = dt.DynamicTraceStage()
        result = stage.ingest(SAMPLE_CAPTURE)
        entity_nodes = [n for n in result.nodes if n.type == "entity"]
        assert len(entity_nodes) == 1
        assert any(e.metadata.relation_type == "observed-in" for e in result.edges)

    def test_ingest_file(self, tmp_path):
        p = tmp_path / "cap.json"
        p.write_text(json.dumps(SAMPLE_CAPTURE))
        stage = dt.DynamicTraceStage()
        result = stage.ingest_file(p)
        assert any(n.type == "dynamic-trace" for n in result.nodes)


class TestCaptureGuards:
    def test_frida_available_returns_bool(self):
        assert isinstance(dt.DynamicTraceStage.frida_available(), bool)

    def test_capture_without_frida_raises_clear_error(self, monkeypatch):
        def _no_frida():
            raise ImportError("No module named 'frida'")

        monkeypatch.setattr(dt, "_import_frida", _no_frida)
        stage = dt.DynamicTraceStage()
        with pytest.raises(StageError) as exc:
            stage.capture("SomeApp", script_source="// noop")
        assert "frida" in str(exc.value).lower()
