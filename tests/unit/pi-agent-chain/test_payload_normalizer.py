"""Payload Normalizer Tests (Gap 1 Production Hardening).

Tests for real-world traffic noise handling:
- Compression (gzip, deflate, brotli, zstd)
- Alternative formats (XML, form-urlencoded, multipart)
- Malformed payload survivability
- Protobuf wire-type probing without schema
- Content-type negotiation edge cases
- Replay determinism after decompression
"""

import gzip
import json
import zlib

import pytest

from pi_agent_chain.models import CompressionType, PayloadFormat
from pi_agent_chain.payload_normalizer import PayloadNormalizer


# ─────────────────────────────────────────────────
def test_gzip_decompression():
    """Gzip-compressed JSON payload is decompressed and parsed."""
    raw = json.dumps({"user": "alice", "id": 42}).encode("utf-8")
    compressed = gzip.compress(raw)

    result = PayloadNormalizer.normalize(
        compressed,
        content_type="application/json",
        content_encoding="gzip",
    )

    assert result.compression == CompressionType.GZIP
    assert result.format_detected == PayloadFormat.JSON
    assert result.is_parseable is True
    assert result.parsed_payload == {"user": "alice", "id": 42}
    assert result.raw_bytes == compressed  # raw preserved


def test_deflate_decompression():
    """Deflate-compressed JSON payload is decompressed and parsed."""
    raw = json.dumps({"status": "ok"}).encode("utf-8")
    compressed = zlib.compress(raw)

    result = PayloadNormalizer.normalize(
        compressed,
        content_type="application/json",
        content_encoding="deflate",
    )

    assert result.compression == CompressionType.DEFLATE
    assert result.is_parseable is True
    assert result.parsed_payload == {"status": "ok"}


def test_brotli_decompression():
    """Brotli-compressed payload is decompressed if brotli is available."""
    try:
        import brotli

        raw = b'{"compressed": true}'
        compressed = brotli.compress(raw)

        result = PayloadNormalizer.normalize(
            compressed,
            content_type="application/json",
            content_encoding="br",
        )

        assert result.compression == CompressionType.BROTLI
        assert result.decompressed_bytes == raw
    except ImportError:
        pytest.skip("brotli not installed")


def test_zstd_decompression():
    """Zstd-compressed payload is decompressed if zstandard is available."""
    try:
        import zstandard as zstd

        raw = b'{"zstd": true}'
        cctx = zstd.ZstdCompressor()
        compressed = cctx.compress(raw)

        result = PayloadNormalizer.normalize(
            compressed,
            content_type="application/json",
            content_encoding="zstd",
        )

        assert result.compression == CompressionType.ZSTD
        assert result.decompressed_bytes == raw
    except ImportError:
        pytest.skip("zstandard not installed")


def test_gzip_magic_byte_detection():
    """Gzip magic bytes detected without Content-Encoding header."""
    raw = json.dumps({"magic": True}).encode("utf-8")
    compressed = gzip.compress(raw)

    result = PayloadNormalizer.normalize(
        compressed,
        content_type="application/json",
        content_encoding="",  # No header
    )

    assert result.compression == CompressionType.GZIP
    assert result.compression_detected_from == "magic_bytes"
    assert result.is_parseable is True


def test_malformed_json_survivability():
    """Malformed JSON is detected but does not crash normalizer."""
    raw = b'{"truncated": '  # Invalid JSON

    result = PayloadNormalizer.normalize(
        raw,
        content_type="application/json",
    )

    assert result.format_detected == PayloadFormat.JSON
    assert result.is_parseable is False
    assert "JSON_PARSE_FAILED" in result.decoding_errors
    assert result.parsed_payload is None


def test_xml_parsing():
    """XML payload is parsed into simplified dict structure."""
    raw = b"<user><name>alice</name><id>42</id></user>"

    result = PayloadNormalizer.normalize(
        raw,
        content_type="application/xml",
    )

    assert result.format_detected == PayloadFormat.XML
    assert result.is_parseable is True
    assert result.parsed_payload == {
        "name": {"_text": "alice"},
        "id": {"_text": "42"},
    }


def test_form_urlencoded_parsing():
    """Form-urlencoded payload is parsed into dict."""
    raw = b"user=alice&id=42&empty="

    result = PayloadNormalizer.normalize(
        raw,
        content_type="application/x-www-form-urlencoded",
    )

    assert result.format_detected == PayloadFormat.FORM_URLENCODED
    assert result.is_parseable is True
    assert result.parsed_payload == {"user": "alice", "id": "42", "empty": ""}


def test_multipart_boundary_extraction():
    """Content-Type header with boundary is extracted."""
    headers = [
        ("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary"),
    ]
    resp_headers = [("Content-Type", "application/json")]

    meta = PayloadNormalizer.extract_content_meta(headers, resp_headers)
    assert meta.boundary == "----WebKitFormBoundary"
    # request_content_type preserves the raw header value; boundary is extracted separately
    assert "multipart/form-data" in meta.request_content_type


def test_protobuf_wire_probe():
    """Protobuf wire-type probing without schema."""
    # Build a simple protobuf-like message manually
    # Field 1, wire type 2 (length-delimited), value "hello"
    # Field 2, wire type 0 (varint), value 42
    raw = b"\x0a\x05hello\x10\x2a"

    result = PayloadNormalizer.normalize(
        raw,
        content_type="application/x-protobuf",
    )

    assert result.format_detected == PayloadFormat.PROTOBUF
    assert result.is_parseable is False  # Schema required
    assert result.parsed_payload is not None
    assert result.parsed_payload["field_count"] == 2
    assert result.decoding_errors == ["PROTOBUF_SCHEMA_REQUIRED"]


def test_protobuf_wire_probe_failure():
    """Non-protobuf data correctly fails wire probe."""
    raw = b"just plain text here"

    result = PayloadNormalizer.normalize(
        raw,
        content_type="application/octet-stream",
    )

    # Should fall back to binary/text, not protobuf
    assert result.format_detected != PayloadFormat.PROTOBUF


def test_content_negotiation_charset():
    """Charset extracted from Content-Type header."""
    req_headers = []
    resp_headers = [("Content-Type", "application/json; charset=utf-16")]

    meta = PayloadNormalizer.extract_content_meta(req_headers, resp_headers)
    assert meta.charset == "utf-16"


def test_replay_determinism_after_decompression():
    """Same compressed payload produces identical normalization results."""
    raw = json.dumps({"seed": 12345}).encode("utf-8")
    compressed = gzip.compress(raw)

    result1 = PayloadNormalizer.normalize(compressed, "application/json", "gzip")
    result2 = PayloadNormalizer.normalize(compressed, "application/json", "gzip")

    # Both should produce identical parsed payloads
    assert result1.parsed_payload == result2.parsed_payload
    assert result1.compression == result2.compression
    assert result1.format_detected == result2.format_detected


def test_truncated_gzip_error_handling():
    """Truncated gzip data is handled gracefully."""
    compressed = gzip.compress(b"valid")[:5]  # Truncate

    result = PayloadNormalizer.normalize(
        compressed,
        content_type="application/json",
        content_encoding="gzip",
    )

    assert result.compression == CompressionType.GZIP
    assert "DECOMPRESSION_FAILED" in result.decoding_errors[0]
    assert result.decompressed_bytes == compressed  # Fallback to raw


def test_heuristic_json_detection():
    """JSON detected by heuristic when Content-Type is missing."""
    raw = b'{"heuristic": true}'

    result = PayloadNormalizer.normalize(
        raw,
        content_type="",  # content-type provided
    )

    assert result.format_detected == PayloadFormat.JSON
    assert result.format_confidence == 0.7  # Heuristic confidence
    assert result.is_parseable is True


def test_heuristic_html_detection():
    """HTML detected by heuristic."""
    raw = b"<html><body>hello</body></html>"

    result = PayloadNormalizer.normalize(
        raw,
        content_type="",  # content-type provided
    )

    assert result.format_detected == PayloadFormat.HTML
    assert result.is_parseable is True


def test_empty_payload():
    """Empty payload handled gracefully."""
    result = PayloadNormalizer.normalize(b"", "application/json")

    assert result.format_detected == PayloadFormat.JSON
    assert result.is_parseable is False
    assert result.parsed_payload is None
