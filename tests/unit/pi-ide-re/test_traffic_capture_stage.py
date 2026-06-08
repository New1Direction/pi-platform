"""
Tests for TrafficCaptureStage (mitmproxy + HAR + WebSocket).

Deterministic ingest is the tested core: HAR (or the native traffic-toolkit
dict) -> content-addressed CapturedRequest nodes, one per ENDPOINT SHAPE
(method+host+path), so repeated calls collapse. Auth is recorded as header
NAMES only - token values never enter the graph. WebSocket flows are detected
and their frames counted. Live capture/replay need mitmproxy/httpx and degrade
to StageError.
"""

from __future__ import annotations

import json

import pytest

from pi_ide_re.stages import traffic_capture as tc
from pi_ide_re.stages.base import StageError

HAR = {
    "log": {
        "version": "1.2",
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/chat?n=1",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer SECRET_A"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/chat?n=2",
                    "headers": [{"name": "Authorization", "value": "Bearer SECRET_B"}],
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            },
            {
                "request": {"method": "GET", "url": "https://api.example.com/health", "headers": []},
                "response": {"status": 200, "content": {"mimeType": "text/plain"}},
            },
        ],
    }
}

NATIVE_WS = {
    "requests": [],
    "responses": [],
    "websockets": [
        {
            "url": "wss://chat.example.com/ws",
            "messages": [
                {"from_client": True, "content": "hello", "type": "text"},
                {"from_client": False, "content": "hi", "type": "text"},
            ],
        }
    ],
}


class TestIngestHar:
    def test_repeated_endpoint_collapses_to_one_node(self):
        result = tc.TrafficCaptureStage().ingest_har(HAR)
        req_nodes = [n for n in result.nodes if n.type == "captured-request"]
        # /v1/chat (x2) collapses; /health distinct -> 2 endpoint nodes
        assert len(req_nodes) == 2

    def test_auth_recorded_as_names_only_no_values(self):
        result = tc.TrafficCaptureStage().ingest_har(HAR)
        req_nodes = [n for n in result.nodes if n.type == "captured-request"]
        blob = json.dumps([json.loads(n.content) for n in req_nodes])
        assert "SECRET_A" not in blob and "SECRET_B" not in blob
        chat = next(n for n in req_nodes if n.title.endswith("/v1/chat"))
        assert "authorization" in json.loads(chat.content)["auth_schemes"]

    def test_determinism_across_reingest(self):
        a = sorted(n.id for n in tc.TrafficCaptureStage().ingest_har(HAR).nodes)
        b = sorted(n.id for n in tc.TrafficCaptureStage().ingest_har(HAR).nodes)
        assert a == b

    def test_summary_endpoints_and_methods(self):
        result = tc.TrafficCaptureStage().ingest_har(HAR)
        assert result.summary["endpoints"] == 2
        assert result.summary["methods"]["POST"] == 2
        assert "authorization" in result.summary["auth_schemes"]


class TestWebSocket:
    def test_websocket_flow_detected_and_frames_counted(self):
        result = tc.TrafficCaptureStage().ingest(NATIVE_WS)
        req_nodes = [n for n in result.nodes if n.type == "captured-request"]
        ws_nodes = [n for n in req_nodes if json.loads(n.content).get("is_websocket")]
        assert len(ws_nodes) == 1
        assert result.summary["websocket_frames"] == 2

    def test_ws_frames_helper_returns_ordered_frames(self):
        frames = tc.TrafficCaptureStage().ws_frames(NATIVE_WS)
        assert [f["content"] for f in frames] == ["hello", "hi"]

    def test_mutate_frame_is_deterministic(self):
        frame = {"from_client": True, "content": "ping", "type": "text"}
        m1 = tc.mutate_frame(frame, ["empty", "duplicate", "overflow"])
        m2 = tc.mutate_frame(frame, ["empty", "duplicate", "overflow"])
        assert m1 == m2
        assert any(f["content"] == "" for f in m1)  # 'empty' mutation present


class TestReplayPlan:
    def test_replay_plan_redacts_auth_values(self):
        plan = tc.TrafficCaptureStage().replay_plan(HAR)
        blob = json.dumps(plan)
        assert "SECRET_A" not in blob
        assert any(h.get("Authorization") == "<redacted>" for p in plan for h in [p.get("headers", {})])

    def test_replay_plan_method_filter(self):
        plan = tc.TrafficCaptureStage().replay_plan(HAR, method_filter="GET")
        assert all(p["method"] == "GET" for p in plan)
        assert len(plan) == 1


class TestLiveGuards:
    def test_capture_without_mitmproxy_raises(self, monkeypatch):
        def _no(*_a, **_k):
            raise ImportError("No module named 'mitmproxy'")

        monkeypatch.setattr(tc, "_import_mitmproxy", _no)
        with pytest.raises(StageError) as exc:
            tc.TrafficCaptureStage().capture(port=8080, duration=0.01)
        assert "mitmproxy" in str(exc.value).lower()

    def test_replay_without_httpx_raises(self, monkeypatch):
        def _no():
            raise ImportError("no httpx")

        monkeypatch.setattr(tc, "_import_http_client", _no)
        with pytest.raises(StageError) as exc:
            tc.TrafficCaptureStage().replay(HAR)
        assert "http" in str(exc.value).lower()
