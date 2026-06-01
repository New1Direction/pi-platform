"""Node 3: Semantic Typing Engine.

Cognitive classification of protocol fields under constitutional governance.
If confidence < threshold, mark UNKNOWN and refuse to freeze (fail-closed).
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from pi_agent_chain.models import (
    ExtractedProtocolSkeleton,
    NormalizedTrafficPacket,
    SemanticField,
    SemanticIRTrace,
)


class SemanticTyperNode:
    """Classify fields into semantic IR with confidence scores."""

    UUIDV4_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    UUIDV1_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    ISO8601_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$")
    JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
    BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
    URL_PATTERN = re.compile(r"^https?://")

    def __init__(self, confidence_threshold: float = 0.87) -> None:
        self.confidence_threshold = confidence_threshold

    def analyze(
        self,
        packet: NormalizedTrafficPacket,
        skeleton: ExtractedProtocolSkeleton,
    ) -> SemanticIRTrace:
        fields: List[SemanticField] = []

        # Classify request payload keys
        fields.extend(self._analyze_body(packet.raw_payload, "request"))
        # Classify response payload keys
        fields.extend(self._analyze_body(packet.response_payload, "response"))
        # Classify query params
        for qk in skeleton.request_query_keys:
            fields.append(
                SemanticField(
                    path=f"query.{qk}",
                    inferred_type="STRING",
                    confidence=0.95,
                    entropy_score=0.0,
                )
            )
        # Classify known auth headers
        for hk, hv in packet.raw_headers:
            if hk.lower() == "authorization":
                fields.append(self._classify_header_field(hk, hv, "header"))

        # Freeze check: every field must meet threshold
        all_frozen = all(f.confidence >= self.confidence_threshold for f in fields)

        return SemanticIRTrace(
            endpoint_template=packet.endpoint_path_template,
            method=packet.method,  # type: ignore[arg-type]
            fields=fields,
            is_frozen=all_frozen,
            frozen_at=datetime.utcnow() if all_frozen else None,
        )

    def _analyze_body(self, body: Optional[str], location: str) -> List[SemanticField]:
        if not body or not body.strip():
            return []
        try:
            data = json.loads(body)
            fields: List[SemanticField] = []
            self._walk_json(data, f"{location}.body", fields)
            return fields
        except json.JSONDecodeError:
            return [
                SemanticField(
                    path=f"{location}.body_raw",
                    inferred_type="UNKNOWN_STR",
                    confidence=0.5,
                    entropy_score=self._shannon_entropy(body),
                    example_value=body[:128],
                )
            ]

    def _walk_json(self, obj: object, path: str, acc: List[SemanticField]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                child = f"{path}.{k}"
                self._walk_json(v, child, acc)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                child = f"{path}[{i}]"
                self._walk_json(v, child, acc)
        else:
            primitive, semantic, confidence, entropy, example = self._classify_primitive(obj)
            acc.append(
                SemanticField(
                    path=path,
                    inferred_type=semantic,
                    confidence=confidence,
                    entropy_score=entropy,
                    example_value=str(example)[:128],
                )
            )

    def _classify_header_field(self, key: str, value: str, location: str) -> SemanticField:
        clean = value
        for prefix in ("Bearer ", "Basic ", "Token ", "ApiKey "):
            if clean.startswith(prefix):
                clean = clean[len(prefix) :]
                break
        primitive, semantic, confidence, entropy, example = self._classify_primitive(clean)
        return SemanticField(
            path=f"{location}.{key}",
            inferred_type=semantic,
            confidence=confidence,
            entropy_score=entropy,
            example_value=str(example)[:16] + "..." if len(str(example)) > 16 else str(example),
        )

    def _classify_primitive(self, value: object) -> Tuple[str, str, float, float, str]:
        s = str(value)
        entropy = self._shannon_entropy(s)

        if isinstance(value, bool):
            return ("boolean", "BOOLEAN", 0.99, entropy, s)

        if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            if isinstance(value, int) and 1_000_000_000 <= value <= 2_000_000_000:
                return ("integer", "UnixTimestamp", 0.95, entropy, s)
            if isinstance(value, str):
                if len(s) == 10 and s.isdigit():
                    return ("integer", "UnixTimestamp", 0.92, entropy, s)
                if len(s) == 13 and s.isdigit():
                    return ("integer", "UnixTimestampMS", 0.92, entropy, s)
            return ("integer", "INTEGER", 0.99, entropy, s)

        if isinstance(value, float):
            return ("number", "NUMBER", 0.99, entropy, s)

        if not isinstance(value, str):
            return ("unknown", "UNKNOWN_STR", 0.5, entropy, s)

        checks = [
            (self.UUIDV4_PATTERN, "UUIDv4", 0.98),
            (self.UUIDV1_PATTERN, "UUIDv1", 0.96),
            (self.ISO8601_PATTERN, "ISO8601", 0.97),
            (self.JWT_PATTERN, "JWT", 0.95),
            (self.EMAIL_PATTERN, "Email", 0.99),
            (self.IPV4_PATTERN, "IPv4", 0.98),
            (self.IPV6_PATTERN, "IPv6", 0.98),
            (self.URL_PATTERN, "URL", 0.97),
        ]
        for pattern, label, conf in checks:
            if pattern.match(s):
                return ("string", label, conf, entropy, s)

        # Base64 requires length >= 16 to avoid matching short words like "Alice"
        if len(s) >= 16 and self.BASE64_PATTERN.match(s):
            return ("string", "Base64", 0.88, entropy, s)

        if entropy > 0.85 and len(s) >= 16:
            if all(c in "0123456789abcdefABCDEF" for c in s):
                return ("string", "HexDigest", 0.82, entropy, s)
            return ("string", "UNKNOWN_HEX", 0.45, entropy, s)

        return ("string", "STRING", 0.90, entropy, s)

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        raw_entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                raw_entropy -= p * math.log2(p)
        alphabet_size = len(freq)
        max_entropy = math.log2(alphabet_size) if alphabet_size > 1 else 1.0
        normalized = raw_entropy / max_entropy if max_entropy > 0 else 0.0
        return round(min(normalized, 1.0), 4)
