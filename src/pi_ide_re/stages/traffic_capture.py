"""
traffic_capture.py - TrafficCaptureStage (mitmproxy + HAR + WebSocket).

Theme 1 P1 (HTTP/WS capture, endpoint + auth extraction, replay) and Theme 2's
WebSocket frame capture + replay/mutation.

Deterministic ingest is the tested core: a HAR 1.2 doc or the native
traffic-toolkit dict ({requests, responses, websockets}) is normalized into
content-addressed ``CapturedRequest`` nodes, ONE per endpoint shape
(method+host+path) so the graph shows the API *surface* rather than every call.
Auth is captured as the set of header NAMES present - token values are never
stored or hashed. WebSocket flows are detected and their frames exposed for
capture/replay/mutation testing.

Live ``capture()`` (mitmproxy) and ``replay()`` (httpx/requests) are thin
adapters that raise StageError when their optional deps are absent. Modeled on
KikkaSkills/analysis/traffic-interception/traffic-toolkit.py (TrafficCapture,
start_proxy, save_traffic/HAR, analyze_traffic, replay_request).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

from ..graph_schema import CapturedRequest, EdgeMetadata, GraphEdge, GraphNode, NodeMetadata, content_hash
from .base import StageError, StageResult

# Header names treated as auth-bearing. We record the NAME, never the value.
_AUTH_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-goog-api-key",
    "x-csrf-token",
    "authentication",
    "x-session-token",
}


def _import_mitmproxy():  # pragma: no cover - import shim (monkeypatched in tests)
    import mitmproxy  # noqa: F401

    return mitmproxy


def _import_http_client():  # pragma: no cover - import shim (monkeypatched in tests)
    import httpx

    return httpx


def _headers_to_dict(headers: Any) -> Dict[str, str]:
    """Accept HAR header arrays ([{name,value}]) or plain dicts."""
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    out: Dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, dict) and "name" in h:
            out[str(h["name"])] = str(h.get("value", ""))
    return out


def _auth_schemes(headers: Dict[str, str]) -> List[str]:
    return sorted({name.lower() for name in headers if name.lower() in _AUTH_HEADERS})


def _captured_request(method: str, url: str, headers: Dict[str, str], *, status=None, mime=None, ws=False):
    parts = urlsplit(url)
    return CapturedRequest(
        method=method,
        url=url,
        host=parts.netloc,
        path=parts.path or "/",
        auth_schemes=_auth_schemes(headers),
        status_code=status,
        content_type=mime,
        is_websocket=ws,
    )


# ---- standalone WS mutation helper (deterministic, for mutation testing) ----


def mutate_frame(frame: Dict[str, Any], mutations: List[str]) -> List[Dict[str, Any]]:
    """Produce deterministic mutated variants of a WebSocket frame.

    Recipe drawn from codex-re/DEBUG_VECTOR.md (WS frame capture + replay as a
    mutation-testing vector). Mutations are applied in the given order so the
    output is reproducible.
    """
    out: List[Dict[str, Any]] = []
    content = str(frame.get("content", ""))
    for m in mutations:
        variant = dict(frame)
        if m == "empty":
            variant["content"] = ""
        elif m == "duplicate":
            variant["content"] = content + content
        elif m == "overflow":
            variant["content"] = content + ("A" * 1024)
        elif m == "truncate":
            variant["content"] = content[: max(0, len(content) // 2)]
        elif m == "flip_direction":
            variant["from_client"] = not bool(frame.get("from_client"))
        else:
            variant["content"] = content
        variant["mutation"] = m
        out.append(variant)
    return out


class TrafficCaptureStage:
    name = "traffic-capture"

    # ---- deterministic ingest ------------------------------------------

    def ingest_har(self, har: Dict[str, Any]) -> StageResult:
        reqs: List[CapturedRequest] = []
        for entry in har.get("log", {}).get("entries", []):
            req = entry.get("request", {})
            resp = entry.get("response", {})
            url = req.get("url", "")
            headers = _headers_to_dict(req.get("headers"))
            is_ws = url.startswith("ws") or entry.get("_resourceType") == "websocket" or "_webSocketMessages" in entry
            reqs.append(
                _captured_request(
                    req.get("method", "GET"),
                    url,
                    headers,
                    status=resp.get("status"),
                    mime=(resp.get("content") or {}).get("mimeType"),
                    ws=is_ws,
                )
            )
        ws_frames = 0
        for entry in har.get("log", {}).get("entries", []):
            ws_frames += len(entry.get("_webSocketMessages", []) or [])
        return self._assemble(reqs, ws_frames)

    def ingest(self, capture: Dict[str, Any]) -> StageResult:
        """Native traffic-toolkit format: {requests, responses, websockets}."""
        if "log" in capture and "entries" in capture.get("log", {}):
            return self.ingest_har(capture)

        reqs: List[CapturedRequest] = []
        resp_by_url: Dict[str, Dict[str, Any]] = {r.get("url"): r for r in capture.get("responses", [])}
        for r in capture.get("requests", []):
            url = r.get("url", "")
            resp = resp_by_url.get(url, {})
            reqs.append(
                _captured_request(
                    r.get("method", "GET"),
                    url,
                    _headers_to_dict(r.get("headers")),
                    status=resp.get("status_code"),
                    mime=r.get("content_type") or resp.get("content_type"),
                )
            )
        ws_frames = 0
        for ws in capture.get("websockets", []):
            msgs = ws.get("messages", [])
            ws_frames += len(msgs)
            reqs.append(_captured_request("GET", ws.get("url", ""), {}, ws=True))
        return self._assemble(reqs, ws_frames)

    def ingest_file(self, path: Union[str, Any]) -> StageResult:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest(json.load(f))

    def _assemble(self, reqs: List[CapturedRequest], ws_frames: int) -> StageResult:
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        methods: Dict[str, int] = {}
        auth_seen: set = set()
        host_nodes: Dict[str, str] = {}

        for r in reqs:
            node = r.to_graph_node()
            nodes[node.id] = node
            methods[r.method.upper()] = methods.get(r.method.upper(), 0) + 1
            auth_seen.update(r.auth_schemes)
            # host entity + contains edge for the API-surface view
            host_id = f"entity/{content_hash({'host': r.host})}"
            if host_id not in host_nodes:
                host_nodes[host_id] = r.host
                nodes[host_id] = GraphNode(
                    id=host_id,
                    type="entity",
                    title=r.host or "(no-host)",
                    content=f"Host observed in traffic capture: {r.host}",
                    metadata=NodeMetadata(source_page="(traffic-capture)", tags=["host", "traffic-capture"]),
                )
            edges.append(
                GraphEdge(
                    source=host_id,
                    target=node.id,
                    metadata=EdgeMetadata(relation_type="contains", created_by=self.name),
                )
            )

        endpoint_nodes = [n for n in nodes.values() if n.type == "captured-request"]
        return StageResult(
            stage=self.name,
            nodes=list(nodes.values()),
            edges=edges,
            summary={
                "endpoints": len(endpoint_nodes),
                "methods": methods,
                "auth_schemes": sorted(auth_seen),
                "websocket_frames": ws_frames,
                "hosts": sorted(host_nodes.values()),
            },
        )

    # ---- WS helpers ----------------------------------------------------

    def ws_frames(self, capture: Dict[str, Any]) -> List[Dict[str, Any]]:
        frames: List[Dict[str, Any]] = []
        for ws in capture.get("websockets", []):
            frames.extend(ws.get("messages", []))
        # HAR-embedded WS frames
        for entry in capture.get("log", {}).get("entries", []):
            frames.extend(entry.get("_webSocketMessages", []) or [])
        return frames

    # ---- replay --------------------------------------------------------

    def replay_plan(
        self, capture: Dict[str, Any], url_filter: Optional[str] = None, method_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Deterministic list of requests to replay, with auth VALUES redacted."""
        entries = capture.get("log", {}).get("entries", [])
        plan: List[Dict[str, Any]] = []
        for entry in entries:
            req = entry.get("request", {})
            method = req.get("method", "GET")
            url = req.get("url", "")
            if method_filter and method.upper() != method_filter.upper():
                continue
            if url_filter and url_filter not in url:
                continue
            headers = _headers_to_dict(req.get("headers"))
            redacted = {k: ("<redacted>" if k.lower() in _AUTH_HEADERS else v) for k, v in headers.items()}
            plan.append({"method": method, "url": url, "headers": redacted})
        return plan

    def replay(self, capture: Dict[str, Any], **filters) -> List[Dict[str, Any]]:
        """Live replay of the plan via httpx. Needs network + httpx."""
        try:
            httpx = _import_http_client()
        except Exception as e:
            raise StageError(
                "an HTTP client (httpx) is required to replay traffic. "
                f"Install with `pip install httpx`. (import failed: {e})"
            ) from e
        plan = self.replay_plan(capture, **filters)
        results = []
        with httpx.Client(timeout=10.0) as client:  # pragma: no cover - network
            for p in plan:
                try:
                    resp = client.request(p["method"], p["url"])
                    results.append({"url": p["url"], "status": resp.status_code})
                except Exception as e:
                    results.append({"url": p["url"], "error": str(e)})
        return results

    # ---- live capture --------------------------------------------------

    def capture(self, port: int = 8080, duration: float = 30.0, output: Optional[str] = None) -> Dict[str, Any]:
        """Run a mitmproxy capture for `duration` seconds. Needs mitmproxy."""
        try:
            _import_mitmproxy()
        except Exception as e:
            raise StageError(
                "mitmproxy is required for live traffic capture. "
                "Install with `pip install mitmproxy`. "
                f"(import failed: {e})"
            ) from e
        # pragma: no cover - exercised only with mitmproxy + a live proxy session
        raise StageError(
            "live mitmproxy capture must be run via the traffic-toolkit proxy addon; "
            "use ingest_har()/ingest() on the resulting HAR for the deterministic graph."
        )
