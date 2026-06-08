"""
Tests for the headless-Ghidra static stage (Theme 1, P2).

Adapts cursor_helpers_post_script.py (strings/functions/xrefs + keyword
detection) so the reports we write by hand (key_strings.txt, structural_report)
are auto-produced. Deterministic core:
- scan_strings(text): keyword detection over a `strings` dump -> BinaryString nodes
- ingest(dump): structured Ghidra dump -> BinaryString + FunctionInterest nodes
  (load addresses are volatile and never affect node identity)
- report renderers reproduce the flat key-strings list
Live Ghidra capture is gated behind a clear StageError.
"""

from __future__ import annotations

import pytest

from pi_ide_re.stages import ghidra_static as gs
from pi_ide_re.stages.base import StageError

STRINGS_DUMP = "\n".join(
    [
        "access_token",
        "SandboxPolicy",
        "this is a boring string",
        "geminiClient",
        "workspace_readwrite",
        "just noise here",
        "mcp_server_config",
    ]
)


class TestScanStrings:
    def test_only_keyword_matching_strings_become_nodes(self):
        result = gs.GhidraStaticStage().scan_strings(STRINGS_DUMP)
        values = {gs._node_value(n) for n in result.nodes if n.type == "binary-string"}
        assert "SandboxPolicy" in values
        assert "access_token" in values
        assert "this is a boring string" not in values
        assert "just noise here" not in values

    def test_context_reflects_matched_keywords(self):
        result = gs.GhidraStaticStage().scan_strings(STRINGS_DUMP)
        node = next(n for n in result.nodes if gs._node_value(n) == "access_token")
        ctx = gs._node_context(node)
        assert "token" in ctx

    def test_scan_is_deterministic(self):
        a = sorted(n.id for n in gs.GhidraStaticStage().scan_strings(STRINGS_DUMP).nodes)
        b = sorted(n.id for n in gs.GhidraStaticStage().scan_strings(STRINGS_DUMP).nodes)
        assert a == b

    def test_custom_keywords(self):
        result = gs.GhidraStaticStage().scan_strings("foobar\nbaz", keywords=["foobar"])
        values = {gs._node_value(n) for n in result.nodes if n.type == "binary-string"}
        assert values == {"foobar"}


class TestDefaultKeywords:
    @pytest.mark.parametrize("kw", ["sandbox", "agent", "tool", "mcp", "token", "secret"])
    def test_default_keyword_set_covers_re_terms(self, kw):
        assert kw in gs.DEFAULT_KEYWORDS


class TestStructuredIngest:
    DUMP = {
        "strings": [
            {"addr": "0x1000", "value": "SandboxPolicy"},
            {"addr": "0x2000", "value": "access_token"},
        ],
        "functions": [
            {"name": "run_agent", "entry": "0x4000"},
            {"name": "spawn_tool", "entry": "0x5000"},
            {"name": "boring_helper", "entry": "0x6000"},
        ],
    }

    def test_produces_string_and_function_nodes(self):
        result = gs.GhidraStaticStage().ingest(self.DUMP)
        assert any(n.type == "binary-string" for n in result.nodes)
        assert any(n.type == "function-interest" for n in result.nodes)

    def test_function_keyword_filtering(self):
        result = gs.GhidraStaticStage().ingest(self.DUMP)
        fn_names = {n.title for n in result.nodes if n.type == "function-interest"}
        assert "run_agent" in fn_names and "spawn_tool" in fn_names
        assert "boring_helper" not in fn_names

    def test_load_addresses_are_volatile(self):
        dump2 = {
            "strings": [{"addr": "0x9999", "value": "SandboxPolicy"}, {"addr": "0xAAAA", "value": "access_token"}],
            "functions": [{"name": "run_agent", "entry": "0xBBBB"}, {"name": "spawn_tool", "entry": "0xCCCC"}],
        }
        a = sorted(n.id for n in gs.GhidraStaticStage().ingest(self.DUMP).nodes)
        b = sorted(n.id for n in gs.GhidraStaticStage().ingest(dump2).nodes)
        assert a == b


class TestReports:
    def test_render_key_strings_is_sorted_unique_flat_list(self):
        stage = gs.GhidraStaticStage()
        result = stage.scan_strings(STRINGS_DUMP + "\naccess_token")  # duplicate
        report = stage.render_key_strings(result)
        lines = [ln for ln in report.splitlines() if ln.strip()]
        assert lines == sorted(set(lines))  # sorted + deduped
        assert "access_token" in lines


class TestLiveGuard:
    def test_capture_ghidra_without_ghidra_raises(self):
        stage = gs.GhidraStaticStage()
        with pytest.raises(StageError) as exc:
            stage.capture_ghidra("/no/such/binary", ghidra_home="/no/such/ghidra")
        assert "ghidra" in str(exc.value).lower()
