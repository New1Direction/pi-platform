"""
Tests for auto-generated FINDINGS.md / METHOD.md (Theme 2, P1).

The docs are graph-driven and deterministic: feed the same KnowledgeGraph and
you get byte-identical markdown (no internal wall-clock). FINDINGS pulls API
surfaces from captured-request nodes, internal codenames from feature-flag +
binary-string nodes, tool schema from traces/hooks. Secrets never appear
(the graph never holds them).
"""

from __future__ import annotations

from pi_ide_re.graph_schema import KnowledgeGraph
from pi_ide_re.methodology import (
    CANONICAL_FINDINGS_SECTIONS,
    generate_findings_md,
    generate_method_md,
    write_methodology,
)
from pi_ide_re.stages import feature_flags as ff
from pi_ide_re.stages import ghidra_static as gs
from pi_ide_re.stages import traffic_capture as tc

HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/chat",
                    "headers": [{"name": "Authorization", "value": "Bearer SECRET"}],
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            }
        ]
    }
}


def _build_graph() -> KnowledgeGraph:
    g = KnowledgeGraph()
    tc.TrafficCaptureStage().ingest_har(HAR).add_to(g)
    ff.FeatureFlagStage().extract("feature.multi_agent_v2 experimental").add_to(g)
    gs.GhidraStaticStage().scan_strings("SandboxPolicy\naccess_token").add_to(g)
    return g


class TestFindings:
    def test_contains_all_canonical_sections(self):
        md = generate_findings_md("antigravity-ide", graph=_build_graph())
        for section in CANONICAL_FINDINGS_SECTIONS:
            assert section in md

    def test_api_surface_listed(self):
        md = generate_findings_md("antigravity-ide", graph=_build_graph())
        assert "POST api.example.com/v1/chat" in md

    def test_internal_codenames_listed(self):
        md = generate_findings_md("antigravity-ide", graph=_build_graph())
        assert "feature.multi_agent_v2" in md
        assert "SandboxPolicy" in md

    def test_target_named(self):
        md = generate_findings_md("antigravity-ide", graph=_build_graph())
        assert "antigravity-ide" in md

    def test_deterministic(self):
        a = generate_findings_md("t", graph=_build_graph())
        b = generate_findings_md("t", graph=_build_graph())
        assert a == b

    def test_no_secret_leak(self):
        md = generate_findings_md("t", graph=_build_graph())
        assert "SECRET" not in md

    def test_handles_empty_graph(self):
        md = generate_findings_md("empty-target", graph=KnowledgeGraph())
        assert "empty-target" in md
        assert "Still Unextracted" in md


class TestMethod:
    def test_contains_reproduction_and_tools(self):
        md = generate_method_md(
            "antigravity-ide", tools=["mitmproxy", "frida"], steps=["Acquire binary", "Attach Frida"]
        )
        assert "Reproduction" in md
        assert "mitmproxy" in md and "frida" in md
        assert "Acquire binary" in md

    def test_includes_five_phase_playbook(self):
        md = generate_method_md("t")
        assert "acquisition" in md.lower()
        assert "static" in md.lower()
        assert "dynamic" in md.lower()

    def test_deterministic(self):
        a = generate_method_md("t", tools=["frida"], steps=["x"])
        b = generate_method_md("t", tools=["frida"], steps=["x"])
        assert a == b


class TestWrite:
    def test_write_methodology_creates_both_files(self, tmp_path):
        paths = write_methodology("antigravity-ide", _build_graph(), root=tmp_path)
        assert paths["findings"].exists()
        assert paths["method"].exists()
        assert "FINDINGS" in paths["findings"].read_text().upper()
