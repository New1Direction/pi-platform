"""Node 2: Deterministic Structural Extractor.

Pure algorithmic flattening. Strips noise, isolates JSON keys, URL params,
and header keys without ever invoking LLM tokens.
"""

from __future__ import annotations

import json
from typing import List, Optional

from pi_agent_chain.models import ExtractedProtocolSkeleton, NormalizedTrafficPacket


class StructuralExtractorNode:
    """Extract structural skeleton from a NormalizedTrafficPacket."""

    def extract(self, packet: NormalizedTrafficPacket) -> ExtractedProtocolSkeleton:
        uri_path = packet.uri.split("?")[0]
        segments = [s for s in uri_path.split("/") if s]

        query_keys: List[str] = []
        if "?" in packet.uri:
            qs = packet.uri.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    query_keys.append(pair.split("=", 1)[0])

        req_header_keys = [k for k, _ in packet.raw_headers]
        resp_header_keys = [k for k, _ in packet.response_headers]

        req_payload_keys = self._flatten_payload(packet.raw_payload)
        if not req_payload_keys and packet.request_payload_norm and packet.request_payload_norm.parsed_payload:
            req_payload_keys = self._flatten_any(packet.request_payload_norm.parsed_payload)

        resp_payload_keys = self._flatten_payload(packet.response_payload)
        if not resp_payload_keys and packet.response_payload_norm and packet.response_payload_norm.parsed_payload:
            resp_payload_keys = self._flatten_any(packet.response_payload_norm.parsed_payload)

        return ExtractedProtocolSkeleton(
            request_uri_segments=segments,
            request_query_keys=query_keys,
            request_header_keys=req_header_keys,
            request_payload_keys_flattened=req_payload_keys,
            response_header_keys=resp_header_keys,
            response_payload_keys_flattened=resp_payload_keys,
        )

    def _flatten_payload(self, payload: Optional[str]) -> List[str]:
        if payload is None:
            return []
        try:
            data = json.loads(payload)
            keys: List[str] = []
            self._walk(data, "", keys)
            return keys
        except json.JSONDecodeError:
            return []

    def _walk(self, obj: object, path: str, acc: List[str]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                child = f"{path}.{k}" if path else k
                if isinstance(v, (dict, list)):
                    self._walk(v, child, acc)
                else:
                    acc.append(child)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                child = f"{path}[{i}]"
                if isinstance(v, (dict, list)):
                    self._walk(v, child, acc)
                else:
                    acc.append(child)

    def _flatten_any(self, payload: object) -> List[str]:
        """Flatten any parseable payload (JSON, XML-dict, form-dict, etc.)."""
        if payload is None:
            return []
        keys: List[str] = []
        self._walk(payload, "", keys)
        return keys
