"""Node 1: Ingress Parser Agent.

Intercepts and normalizes raw L7 network streams into a strict
NormalizedTrafficPacket. No hidden memory.

Gap 1 Update: Integrates PayloadNormalizer for content-type negotiation,
compression handling, and alternative format detection.
"""

from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple

from pi_agent_chain.models import NormalizedTrafficPacket
from pi_agent_chain.payload_normalizer import PayloadNormalizer


class IngressParserNode:
    """Parse raw HTTP text blobs into NormalizedTrafficPacket."""

    def __init__(self, max_body_size: int = 10_000_000) -> None:
        self.max_body_size = max_body_size

    def parse_raw(
        self,
        raw_request: str,
        raw_response: str,
        url_override: Optional[str] = None,
    ) -> NormalizedTrafficPacket:
        method, path, req_headers, req_body = self._split_request(raw_request)
        status_line, resp_headers, resp_body = self._split_response(raw_response)

        status_code = self._extract_status_code(status_line)
        host = self._extract_host(req_headers)
        scheme = "https" if url_override and url_override.startswith("https") else "http"
        uri = (url_override or f"{scheme}://{host}") + path

        # Gap 1: Content negotiation metadata
        content_meta = PayloadNormalizer.extract_content_meta(req_headers, resp_headers)

        # Gap 1: Payload normalization (decompression + format detection)
        req_payload_bytes = req_body.encode("utf-8", errors="replace") if req_body else b""
        resp_payload_bytes = resp_body.encode("utf-8", errors="replace") if resp_body else b""

        req_norm = PayloadNormalizer.normalize(
            req_payload_bytes,
            content_type=content_meta.request_content_type,
            content_encoding="",
            transfer_encoding=content_meta.transfer_encoding,
        )
        resp_norm = PayloadNormalizer.normalize(
            resp_payload_bytes,
            content_type=content_meta.response_content_type,
            content_encoding=content_meta.response_content_encoding,
            transfer_encoding=content_meta.transfer_encoding,
        )

        return NormalizedTrafficPacket(
            timestamp=int(time.time()),
            method=method.upper(),
            uri=uri,
            raw_headers=req_headers,
            raw_payload=self._sanitize_body(req_body),
            response_status=status_code,
            response_headers=resp_headers,
            response_payload=self._sanitize_body(resp_body),
            host=host,
            scheme=scheme,
            content_meta=content_meta,
            request_payload_norm=req_norm,
            response_payload_norm=resp_norm,
        )

    def _split_request(self, raw: str) -> tuple[str, str, List[Tuple[str, str]], Optional[str]]:
        lines = raw.splitlines()
        if not lines:
            return ("GET", "/", [], None)

        start_line = lines[0].strip()
        parts = start_line.split()
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers: List[Tuple[str, str]] = []
        body: Optional[str] = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body = "\n".join(lines[i + 1 :])
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers.append((key.strip(), value.strip()))

        return (method, path, headers, body)

    def _split_response(self, raw: str) -> tuple[str, List[Tuple[str, str]], Optional[str]]:
        lines = raw.splitlines()
        if not lines:
            return ("HTTP/1.1 200 OK", [], None)

        start_line = lines[0].strip()
        headers: List[Tuple[str, str]] = []
        body: Optional[str] = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body = "\n".join(lines[i + 1 :])
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers.append((key.strip(), value.strip()))

        return (start_line, headers, body)

    def _extract_status_code(self, status_line: str) -> int:
        match = re.search(r"HTTP/\d\.\d\s+(\d{3})", status_line)
        return int(match.group(1)) if match else 0

    def _extract_host(self, headers: List[Tuple[str, str]]) -> str:
        for key, value in headers:
            if key.lower() == "host":
                return value
        return "unknown"

    def _sanitize_body(self, body: Optional[str]) -> Optional[str]:
        if body is None:
            return None
        if len(body) > self.max_body_size:
            return body[: self.max_body_size] + "\n[TRUNCATED]"
        # JSON-style redaction: "password": "secret" -> "password": "***REDACTED***"
        redacted = re.sub(
            r"([\"'])(password|token|secret|key|authorization)\1\s*[:=]\s*([\"'])[^\"']+\3",
            r"\1\2\1: \3***REDACTED***\3",
            body,
            flags=re.IGNORECASE,
        )
        # Form-urlencoded redaction: password=secret -> password=***REDACTED***
        redacted = re.sub(
            r"(?<=[?&])(password|token|secret|key|authorization)=([^&\s]+)",
            r"\1=***REDACTED***",
            redacted,
            flags=re.IGNORECASE,
        )
        return redacted
