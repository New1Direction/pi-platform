"""
Tests for the formalized 5-phase RE playbook (Theme 2, P2).

A Campaign runs the stages in the canonical phase order (acquisition -> static
-> dynamic-capture -> protocol-mapping -> feature-extraction), merging each
stage's content-addressed nodes into one graph and recording per-phase
provenance. Same inputs -> same graph (determinism), so a campaign is
replayable from its saved artifacts.
"""

from __future__ import annotations

from pi_ide_re.playbook import PHASES, Campaign

HAR = {
    "log": {
        "entries": [
            {
                "request": {"method": "POST", "url": "https://api.example.com/v1/chat", "headers": []},
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            }
        ]
    }
}
TRACE = {
    "target": "Acme IDE",
    "messages": [{"type": "send", "payload": {"hook": "objc_msgSend", "selector": "toolCall:"}}],
}


class TestPhases:
    def test_canonical_phase_order(self):
        assert PHASES == ["acquisition", "static", "dynamic-capture", "protocol-mapping", "feature-extraction"]


class TestCampaign:
    def _run(self, root):
        c = Campaign("acme-ide", root=root)
        c.acquire(sha256="abc123", size=42, version="1.0.0")
        c.static(strings_text="SandboxPolicy\naccess_token")
        c.dynamic(capture=TRACE)
        c.protocol(har=HAR)
        c.features(text="feature.multi_agent_v2 experimental")
        return c

    def test_runs_all_phases_and_merges_nodes(self, tmp_path):
        c = self._run(tmp_path)
        types = {n.type for n in c.graph.nodes.values()}
        assert "binary-string" in types
        assert "captured-request" in types
        assert "dynamic-trace" in types
        assert "feature-flag" in types

    def test_phase_records_in_order(self, tmp_path):
        c = self._run(tmp_path)
        phases_run = [r.phase for r in c.records]
        assert phases_run == PHASES

    def test_assemble_summary(self, tmp_path):
        c = self._run(tmp_path)
        summary = c.assemble()
        assert summary["target"] == "acme-ide"
        assert summary["nodes"] == len(c.graph.nodes)
        assert set(summary["by_type"]).issuperset({"binary-string", "captured-request", "feature-flag"})
        assert summary["phases"] == PHASES

    def test_determinism_same_inputs_same_graph(self, tmp_path):
        a = sorted(self._run(tmp_path / "a").graph.nodes.keys())
        b = sorted(self._run(tmp_path / "b").graph.nodes.keys())
        assert a == b

    def test_acquire_records_provenance_node(self, tmp_path):
        c = Campaign("acme-ide", root=tmp_path)
        c.acquire(sha256="deadbeef", size=100, version="2.1")
        artifact_nodes = [n for n in c.graph.nodes.values() if n.type == "code-artifact"]
        assert len(artifact_nodes) == 1
        assert "deadbeef" in artifact_nodes[0].content

    def test_persist_and_write_docs(self, tmp_path):
        c = self._run(tmp_path)
        c.persist()
        assert (tmp_path / "acme-ide" / "knowledge_graph.json").exists()
        paths = c.write_docs()
        assert paths["findings"].exists() and paths["method"].exists()
        # FINDINGS reflects the captured endpoint
        assert "api.example.com/v1/chat" in paths["findings"].read_text()
