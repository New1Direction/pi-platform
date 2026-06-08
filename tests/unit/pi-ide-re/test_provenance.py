"""
Tests for provenance sidecars (Theme 3, P3).

Every RE output (acquisition / analysis / patch) gets a .usage.json sidecar
linking it to its phase + originating agent (+ optional ledger ref), modeled on
the .usage.json convention. Deterministic given an explicit captured_at.
"""

from __future__ import annotations

import json

from pi_ide_re.provenance import read_usage_sidecar, write_usage_sidecar


class TestSidecar:
    def test_writes_sidecar_next_to_output(self, tmp_path):
        out = tmp_path / "key_strings.txt"
        out.write_text("data")
        side = write_usage_sidecar(out, phase="static", agent="ghidra-static", kind="analysis")
        assert side == out.with_suffix(out.suffix + ".usage.json")
        assert side.exists()

    def test_record_fields(self, tmp_path):
        out = tmp_path / "o.bin"
        out.write_text("x")
        side = write_usage_sidecar(
            out, phase="acquisition", agent="acquire", kind="binary", captured_at="2026-06-01T00:00:00Z"
        )
        rec = json.loads(side.read_text())
        assert rec["phase"] == "acquisition"
        assert rec["agent"] == "acquire"
        assert rec["kind"] == "binary"
        assert rec["captured_at"] == "2026-06-01T00:00:00Z"
        assert rec["output"] == "o.bin"

    def test_deterministic_except_captured_at(self, tmp_path):
        out = tmp_path / "o.txt"
        out.write_text("x")
        a = write_usage_sidecar(out, phase="p", agent="a", kind="k", captured_at="T1").read_text()
        b = write_usage_sidecar(out, phase="p", agent="a", kind="k", captured_at="T1").read_text()
        assert a == b

    def test_optional_ledger_ref_and_extra(self, tmp_path):
        out = tmp_path / "o.txt"
        out.write_text("x")
        side = write_usage_sidecar(
            out, phase="p", agent="a", kind="patch", ledger_ref="chain:123#4", extra={"sha256": "deadbeef"}
        )
        rec = json.loads(side.read_text())
        assert rec["ledger_ref"] == "chain:123#4"
        assert rec["extra"]["sha256"] == "deadbeef"

    def test_round_trip_read(self, tmp_path):
        out = tmp_path / "o.txt"
        out.write_text("x")
        write_usage_sidecar(out, phase="p", agent="a", kind="k", captured_at="T")
        rec = read_usage_sidecar(out)
        assert rec["phase"] == "p"
