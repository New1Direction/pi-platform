"""Node 0: Acquisition Gateway.

Pure normalization boundary. Converts volatile live traffic (mitmproxy flows,
HAR, PCAP) into deterministic GovernedPackets.

NEVER performs inference.
NEVER performs semantic typing.
NEVER mutates payload meaningfully.
NEVER classifies behavior.

Only establishes runtime truth: "This packet was observed."
"""

from __future__ import annotations

import hashlib
import json
import uuid
import zlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pi_agent_chain.models import (
    GovernedPacket,
    NormalizedTrafficPacket,
    ReplayClass,
    RuntimeTruthEnvelope,
)


class AcquisitionGatewayNode:
    """Canonical acquisition boundary for deterministic semantic runtime."""

    def __init__(self, source: str = "MITMPROXY") -> None:
        self.source = source

    def from_mitmproxy_flow(self, flow: Dict[str, Any]) -> GovernedPacket:
        """Convert a raw mitmproxy flow dict into a canonical GovernedPacket."""
        request = flow.get("request", {})
        response = flow.get("response", {})

        method = request.get("method", "GET").upper()
        scheme = request.get("scheme", "https")
        host = request.get("host", "unknown")
        port = request.get("port", 443 if scheme == "https" else 80)
        path = request.get("path", "/")

        uri = f"{scheme}://{host}:{port}{path}"

        req_headers_raw = request.get("headers", [])
        req_headers = self._canonicalize_headers(req_headers_raw)
        req_body = self._extract_body(request)

        resp_status = response.get("status_code", 0)
        resp_headers_raw = response.get("headers", [])
        resp_headers = self._canonicalize_headers(resp_headers_raw)
        resp_body = self._extract_body(response)

        packet = NormalizedTrafficPacket(
            timestamp=int(datetime.utcnow().timestamp()),
            method=method,  # type: ignore[arg-type]
            uri=uri,
            raw_headers=req_headers,
            raw_payload=req_body,
            response_status=resp_status,
            response_headers=resp_headers,
            response_payload=resp_body,
            host=host,
            scheme=scheme,
        )

        # Compute raw packet hash (includes volatile metadata)
        packet_hash = hashlib.sha256(packet.model_dump_json().encode()).hexdigest()

        # Compute canonical hash (excludes volatile metadata, sorted deterministically)
        canonical_payload = json.dumps(
            {
                "method": packet.method,
                "uri": packet.uri,
                "raw_headers": packet.raw_headers,
                "raw_payload": packet.raw_payload,
                "response_status": packet.response_status,
                "response_headers": packet.response_headers,
                "response_payload": packet.response_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        canonical_hash = hashlib.sha256(canonical_payload.encode()).hexdigest()

        # Replay safety classification
        replay_class = self._classify_replay_safety(method, path, req_headers)

        truth = RuntimeTruthEnvelope(
            capture_id=str(uuid.uuid4()),
            flow_id=flow.get("id", str(uuid.uuid4())),
            observed_at=datetime.utcnow(),
            transport=self._detect_transport(flow),
            tls=scheme == "https",
            source=self.source,  # type: ignore[arg-type]
            packet_hash=packet_hash,
            canonical_hash=canonical_hash,
            replay_class=replay_class,
            canonicalized_headers=req_headers,
            content_type_normalized=self._normalize_content_type(req_headers),
            body_encoding=self._detect_body_encoding(req_body),
        )

        return GovernedPacket(truth=truth, packet=packet)

    def from_raw_http_pair(
        self,
        raw_request: str,
        raw_response: str,
        url_override: Optional[str] = None,
    ) -> GovernedPacket:
        """Convert raw HTTP text blobs into a canonical GovernedPacket.

        Used for manual / fixture ingestion.
        """
        from pi_agent_chain.nodes.ingress_parser import IngressParserNode

        parser = IngressParserNode()
        packet = parser.parse_raw(raw_request, raw_response, url_override=url_override)

        packet_hash = hashlib.sha256(packet.model_dump_json().encode()).hexdigest()

        canonical_payload = json.dumps(
            {
                "method": packet.method,
                "uri": packet.uri,
                "raw_headers": packet.raw_headers,
                "raw_payload": packet.raw_payload,
                "response_status": packet.response_status,
                "response_headers": packet.response_headers,
                "response_payload": packet.response_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        canonical_hash = hashlib.sha256(canonical_payload.encode()).hexdigest()

        replay_class = self._classify_replay_safety(packet.method, packet.endpoint_path_template, packet.raw_headers)

        truth = RuntimeTruthEnvelope(
            capture_id=str(uuid.uuid4()),
            flow_id=str(uuid.uuid4()),
            observed_at=datetime.utcnow(),
            transport="HTTP1",
            tls=packet.scheme == "https",
            source="MANUAL",  # type: ignore[arg-type]
            packet_hash=packet_hash,
            canonical_hash=canonical_hash,
            replay_class=replay_class,
            canonicalized_headers=packet.raw_headers,
            content_type_normalized=self._normalize_content_type(packet.raw_headers),
            body_encoding=self._detect_body_encoding(packet.raw_payload),
        )

        return GovernedPacket(truth=truth, packet=packet)

    @staticmethod
    def _canonicalize_headers(
        headers: List[Any],
    ) -> List[Tuple[str, str]]:
        """Sort headers deterministically by key (lowercase), preserving multi-value."""
        parsed: List[Tuple[str, str]] = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key, value = str(item[0]), str(item[1])
                parsed.append((key.lower(), value))
            elif isinstance(item, dict):
                for k, v in item.items():
                    parsed.append((str(k).lower(), str(v)))
        parsed.sort(key=lambda x: x[0])
        return parsed

    @staticmethod
    def _extract_body(message: Dict[str, Any]) -> Optional[str]:
        """Extract and decompress body if necessary."""
        content = message.get("content")
        if content is None:
            return None

        # Handle bytes
        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8", errors="replace")
            except Exception:
                return None

        # Handle base64-encoded content from mitmproxy dump
        if isinstance(content, str) and content.startswith("b'"):
            try:
                content = content[2:-1] if content.endswith("'") else content[2:]
            except Exception:
                pass

        # Check for gzip/deflate
        headers = message.get("headers", [])
        encoding = None
        for h in headers:
            if isinstance(h, (list, tuple)) and len(h) >= 2:
                if str(h[0]).lower() == "content-encoding":
                    encoding = str(h[1]).lower()
                    break

        if encoding in ("gzip", "deflate") and isinstance(content, bytes):
            try:
                content = zlib.decompress(content, zlib.MAX_WBITS | 16).decode("utf-8", errors="replace")
            except Exception:
                pass

        return content if isinstance(content, str) else str(content)

    @staticmethod
    def _normalize_content_type(
        headers: List[Tuple[str, str]],
    ) -> Optional[str]:
        for key, value in headers:
            if key.lower() == "content-type":
                # Strip charset suffix for canonical type
                ct = value.split(";")[0].strip().lower()
                return ct
        return None

    @staticmethod
    def _detect_body_encoding(body: Optional[str]) -> str:
        if body is None:
            return "unknown"
        try:
            body.encode("utf-8")
            return "utf-8"
        except UnicodeEncodeError:
            return "binary"

    @staticmethod
    def _detect_transport(flow: Dict[str, Any]) -> str:
        http_version = flow.get("request", {}).get("http_version", "HTTP/1.1")
        if "2" in http_version:
            return "HTTP2"
        if "3" in http_version:
            return "HTTP3"
        return "HTTP1"

    @staticmethod
    def _classify_replay_safety(
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
    ) -> str:
        """Classify replay safety based on HTTP method and path heuristics."""
        method = method.upper()

        # Pure replayable: GET/HEAD/OPTIONS on read-only paths
        read_only_indicators = [
            "get",
            "list",
            "fetch",
            "search",
            "query",
            "read",
            "find",
            "lookup",
            "retrieve",
            "view",
        ]
        path_lower = path.lower()
        is_read_path = any(ind in path_lower for ind in read_only_indicators)

        if method in ("GET", "HEAD", "OPTIONS") and is_read_path:
            return ReplayClass.PURE_REPLAYABLE

        if method in ("GET", "HEAD", "OPTIONS"):
            return ReplayClass.IDEMPOTENT

        # Non-replayable: DELETE or destructive mutations
        if method == "DELETE":
            return ReplayClass.NON_REPLAYABLE

        # Side-effect risk: POST/PUT/PATCH that look like mutations
        mutation_indicators = [
            "create",
            "post",
            "submit",
            "write",
            "update",
            "delete",
            "remove",
            "destroy",
            "add",
            "insert",
            "modify",
            "change",
        ]
        if any(ind in path_lower for ind in mutation_indicators):
            return ReplayClass.SIDE_EFFECT_RISK

        if method in ("POST", "PUT", "PATCH"):
            return ReplayClass.SIDE_EFFECT_RISK

        return ReplayClass.NON_REPLAYABLE
