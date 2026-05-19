"""Payload Normalizer — Gap 1: Real-World Traffic Noise.

Handles content-type negotiation, compression (gzip, brotli, deflate), format detection,
and normalization of alternative payload formats (XML, form, protobuf best-effort).

Key constraints:
- Raw bytes are ALWAYS preserved for hash integrity.
- Decompressed content is provided for downstream extraction.
- Format detection is heuristic + header-based, never LLM-inferred.
- Protobuf without schema is wire-type parsed only — field names remain unknown.
"""

import gzip
import json
import re
import xml.etree.ElementTree as ET
import zlib
from collections import defaultdict
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

from pi_agent_chain.models import (
    CompressionType,
    ContentNegotiationMeta,
    PayloadFormat,
    PayloadNormalization,
)


class PayloadNormalizer:
    """Deterministic payload normalization for real-world traffic.

    NOT a parser. NOT a semantic extractor. Just a normalization boundary
    that produces consistent, decompressed, format-tagged payloads.
    """

    # Magic byte signatures for heuristic detection
    MAGIC_SIGNATURES = {
        b"\x1f\x8b": CompressionType.GZIP,          # gzip magic
        b"\x78\x9c": CompressionType.DEFLATE,     # zlib/deflate (raw)
        b"\x78\x01": CompressionType.DEFLATE,      # zlib no compression
        b"\x78\xda": CompressionType.DEFLATE,      # zlib best compression
        b"\x28\xb5\x2f\xfd": CompressionType.ZSTD,  # zstd magic
        # Brotli has no magic bytes — detection from content-encoding only
    }

    # Content-Type → format mapping (partial, extensible)
    CONTENT_TYPE_MAP = {
        "application/json": PayloadFormat.JSON,
        "application/xml": PayloadFormat.XML,
        "text/xml": PayloadFormat.XML_TEXT,
        "application/x-www-form-urlencoded": PayloadFormat.FORM_URLENCODED,
        "multipart/form-data": PayloadFormat.FORM_MULTIPART,
        "application/x-protobuf": PayloadFormat.PROTOBUF,
        "application/grpc": PayloadFormat.GRPC,
        "application/grpc+proto": PayloadFormat.GRPC_PROTO,
        "text/plain": PayloadFormat.TEXT,
        "text/html": PayloadFormat.HTML,
        "application/octet-stream": PayloadFormat.BINARY,
    }

    @classmethod
    def normalize(
        cls,
        raw_bytes: bytes,
        content_type: str = "",
        content_encoding: str = "",
        transfer_encoding: str = "",
    ) -> PayloadNormalization:
        """Normalize a single payload byte stream.

        Returns a PayloadNormalization with:
        - raw_bytes preserved
        - decompression applied if detected
        - format classification from headers + heuristics
        - parsed_payload for structured formats (JSON, XML, form)
        """
        result = PayloadNormalization(
            raw_bytes=raw_bytes,
            raw_length=len(raw_bytes),
        )

        # Step 1: Detect and apply compression
        compression, detected_from = cls._detect_compression(
            raw_bytes, content_encoding
        )
        result.compression = compression
        result.compression_detected_from = detected_from

        if compression != CompressionType.NONE and raw_bytes:
            decompressed = cls._decompress(raw_bytes, compression)
            if decompressed is not None:
                result.decompressed_bytes = decompressed
                result.decompressed_length = len(decompressed)
            else:
                result.decoding_errors.append(f"DECOMPRESSION_FAILED:{compression}")
                result.decompressed_bytes = raw_bytes
                result.decompressed_length = len(raw_bytes)
        else:
            result.decompressed_bytes = raw_bytes
            result.decompressed_length = len(raw_bytes)

        working_bytes = result.decompressed_bytes or b""

        # Step 2: Detect format
        fmt, confidence = cls._detect_format(
            working_bytes, content_type
        )
        result.format_detected = fmt
        result.format_confidence = confidence

        # Step 3: Parse if structured
        if fmt in (PayloadFormat.JSON,):
            parsed = cls._parse_json(working_bytes)
            if parsed is not None:
                result.parsed_payload = parsed
                result.is_parseable = True
            else:
                result.decoding_errors.append("JSON_PARSE_FAILED")
        elif fmt in (PayloadFormat.XML, PayloadFormat.XML_TEXT):
            parsed = cls._parse_xml(working_bytes)
            if parsed is not None:
                result.parsed_payload = parsed
                result.is_parseable = True
            else:
                result.decoding_errors.append("XML_PARSE_FAILED")
        elif fmt == PayloadFormat.FORM_URLENCODED:
            parsed = cls._parse_form_urlencoded(working_bytes)
            if parsed is not None:
                result.parsed_payload = parsed
                result.is_parseable = True
            else:
                result.decoding_errors.append("FORM_PARSE_FAILED")
        elif fmt == PayloadFormat.TEXT:
            try:
                result.parsed_payload = working_bytes.decode("utf-8", errors="replace")
                result.is_parseable = True
            except Exception:
                result.decoding_errors.append("TEXT_DECODE_FAILED")
        elif fmt == PayloadFormat.HTML:
            try:
                result.parsed_payload = working_bytes.decode("utf-8", errors="replace")
                result.is_parseable = True
            except Exception:
                result.decoding_errors.append("HTML_DECODE_FAILED")
        elif fmt in (PayloadFormat.PROTOBUF, PayloadFormat.GRPC, PayloadFormat.GRPC_PROTO):
            # Best-effort: detect wire-type structure, but cannot parse without schema
            wire_info = cls._probe_protobuf_wire(working_bytes)
            if wire_info:
                result.parsed_payload = wire_info
                result.is_parseable = False  # Schema required for true parsing
                result.decoding_errors.append("PROTOBUF_SCHEMA_REQUIRED")
            else:
                result.decoding_errors.append("PROTOBUF_WIRE_PROBE_FAILED")
        else:
            result.decoding_errors.append(f"UNSUPPORTED_FORMAT:{fmt}")

        return result

    @classmethod
    def extract_content_meta(
        cls,
        request_headers: List[Tuple[str, str]],
        response_headers: List[Tuple[str, str]],
    ) -> ContentNegotiationMeta:
        """Extract content negotiation metadata from request/response headers."""
        meta = ContentNegotiationMeta()
        rh = {k.lower(): v for k, v in request_headers}
        rsh = {k.lower(): v for k, v in response_headers}

        meta.request_accept = rh.get("accept", "")
        meta.request_content_type = rh.get("content-type", "")
        meta.response_content_type = rsh.get("content-type", "")
        meta.response_content_encoding = rsh.get("content-encoding", "")
        meta.transfer_encoding = rsh.get("transfer-encoding", "")

        # Extract charset and boundary from both request and response headers
        for header_name, header_value in response_headers + request_headers:
            if header_name.lower() == "content-type":
                m = re.search(r"charset=([^;\s]+)", header_value, re.IGNORECASE)
                if m:
                    meta.charset = m.group(1).strip('"\'')
                # Extract boundary for multipart
                m = re.search(r'boundary=([^;\s]+)', header_value, re.IGNORECASE)
                if m:
                    meta.boundary = m.group(1).strip('"\'')
                # Continue — do NOT break; both request and response may carry Content-Type

        return meta

    @classmethod
    def _detect_compression(
        cls, raw_bytes: bytes, content_encoding: str
    ) -> Tuple[str, str]:
        """Detect compression from content-encoding header or magic bytes.

        Returns (compression_type, detected_from_source).
        """
        ce = content_encoding.lower().strip() if content_encoding else ""
        if ce:
            if "gzip" in ce:
                return (CompressionType.GZIP, "content-encoding")
            if "deflate" in ce:
                return (CompressionType.DEFLATE, "content-encoding")
            if "br" in ce:
                return (CompressionType.BROTLI, "content-encoding")
            if "zstd" in ce:
                return (CompressionType.ZSTD, "content-encoding")

        # Heuristic: check magic bytes
        if raw_bytes:
            for magic, ctype in cls.MAGIC_SIGNATURES.items():
                if raw_bytes.startswith(magic):
                    return (ctype, "magic_bytes")

        return (CompressionType.NONE, "none")

    @classmethod
    def _decompress(cls, data: bytes, compression: str) -> Optional[bytes]:
        """Decompress payload using detected compression type."""
        if compression == CompressionType.GZIP:
            try:
                return gzip.decompress(data)
            except Exception:
                return None
        elif compression == CompressionType.DEFLATE:
            try:
                return zlib.decompress(data)
            except Exception:
                try:
                    return zlib.decompress(data, -zlib.MAX_WBITS)
                except Exception:
                    return None
        elif compression == CompressionType.BROTLI:
            try:
                import brotli
                return brotli.decompress(data)
            except ImportError:
                return None  # brotli optional dependency
            except Exception:
                return None
        elif compression == CompressionType.ZSTD:
            try:
                import zstandard as zstd
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data)
            except ImportError:
                return None
            except Exception:
                return None
        return data

    @classmethod
    def _detect_format(
        cls, data: bytes, content_type: str
    ) -> Tuple[str, float]:
        """Detect payload format from Content-Type header and heuristics.

        Confidence scoring:
        - Content-Type exact match: 1.0
        - Content-Type partial match: 0.7
        - Magic/heuristic detection: 0.5
        - Fallback: 0.3
        """
        ct = content_type.lower().strip() if content_type else ""
        # Strip charset, boundary etc.
        ct_clean = ct.split(";")[0].strip()

        if ct_clean in cls.CONTENT_TYPE_MAP:
            return (cls.CONTENT_TYPE_MAP[ct_clean], 1.0)

        # Heuristic detection from body content
        if not data:
            return (PayloadFormat.UNKNOWN, 0.0)

        text = None
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            pass

        if text:
            stripped = text.strip()
            if stripped.startswith(("{", "[")):
                return (PayloadFormat.JSON, 0.7)
            if stripped.startswith("<"):
                if "<?xml" in stripped[:100].lower():
                    return (PayloadFormat.XML, 0.7)
                return (PayloadFormat.HTML, 0.5)
            if "=" in stripped and "&" in stripped and ";" not in stripped[:20]:
                return (PayloadFormat.FORM_URLENCODED, 0.5)
            if stripped and all(c in "0123456789abcdefABCDEF \n\r\t" for c in stripped[:100]):
                return (PayloadFormat.TEXT, 0.3)

        # Protobuf/grpc heuristic: non-printable bytes with valid wire tags
        wire_probe = cls._probe_protobuf_wire(data)
        if wire_probe and wire_probe.get("field_count", 0) > 0:
            return (PayloadFormat.PROTOBUF, 0.4)

        return (PayloadFormat.BINARY, 0.3)

    @classmethod
    def _parse_json(cls, data: bytes) -> Optional[Any]:
        """Parse JSON payload. Returns dict/list or None."""
        try:
            text = data.decode("utf-8", errors="replace")
            return json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    @classmethod
    def _parse_xml(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse XML payload into a simplified dict structure.

        NOT a full XML → JSON conversion. Just enough for field path extraction.
        """
        try:
            text = data.decode("utf-8", errors="replace")
            root = ET.fromstring(text)
            return cls._xml_to_dict(root)
        except ET.ParseError:
            return None
        except Exception:
            return None

    @classmethod
    def _xml_to_dict(cls, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dict (recursive)."""
        result: Dict[str, Any] = {}
        if element.text and element.text.strip():
            result["_text"] = element.text.strip()
        for key, value in element.attrib.items():
            result[f"@{key}"] = value
        for child in element:
            child_dict = cls._xml_to_dict(child)
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_dict)
            else:
                result[tag] = child_dict
        return result

    @classmethod
    def _parse_form_urlencoded(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse application/x-www-form-urlencoded payload."""
        try:
            text = data.decode("utf-8", errors="replace")
            from urllib.parse import parse_qs
            parsed = parse_qs(text, keep_blank_values=True)
            # Flatten single-value lists
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        except Exception:
            return None

    @classmethod
    def _probe_protobuf_wire(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """Best-effort protobuf wire-format probing without a schema.

        Detects field numbers and wire types (varint, fixed64, length-delimited, etc.)
        but cannot determine field names or message types.

        Returns {"field_count": int, "fields": [{"number": int, "wire_type": int}]}
        or None if data does not look like protobuf.
        """
        if len(data) < 2:
            return None

        fields = []
        pos = 0
        max_probe = min(len(data), 4096)  # Limit probe depth

        while pos < max_probe:
            # Parse varint tag
            tag = 0
            shift = 0
            tag_bytes_consumed = 0
            while pos < max_probe:
                if pos >= len(data):
                    break
                byte = data[pos]
                tag |= (byte & 0x7F) << shift
                pos += 1
                tag_bytes_consumed += 1
                if not (byte & 0x80):
                    break
                shift += 7
                if shift > 28:
                    break  # Invalid varint
            else:
                break

            field_number = tag >> 3
            wire_type = tag & 0x07

            if field_number == 0 or field_number > 536870911:
                # Not a valid protobuf tag
                break

            fields.append({"number": field_number, "wire_type": wire_type})

            # Skip value based on wire type
            if wire_type == 0:  # Varint
                while pos < max_probe and pos < len(data) and (data[pos] & 0x80):
                    pos += 1
                pos += 1
            elif wire_type == 1:  # 64-bit
                pos += 8
            elif wire_type == 2:  # Length-delimited
                length = 0
                shift = 0
                while pos < max_probe and pos < len(data):
                    byte = data[pos]
                    pos += 1
                    length |= (byte & 0x7F) << shift
                    if not (byte & 0x80):
                        break
                    shift += 7
                pos += length
            elif wire_type == 5:  # 32-bit
                pos += 4
            else:
                break  # Invalid wire type

            if pos > max_probe:
                break

        if len(fields) >= 1:
            return {"field_count": len(fields), "fields": fields[:64]}
        return None
