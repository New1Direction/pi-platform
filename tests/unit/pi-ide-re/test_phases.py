"""
Tests for the phased campaign layout (Theme 3, P2).

Generates re/<target>/phases/NN_*.md from the campaign graph, following the
hermes-re NN_Title.md convention (acquisition -> static -> behavior -> protocol
-> threat-model -> features) plus a 00_index MOC. Deterministic: same graph ->
byte-identical phase docs.
"""

from __future__ import annotations

from pi_ide_re.phases import CANONICAL_PHASES, generate_phase_docs, write_phase_docs
from pi_ide_re.playbook import Campaign

HAR = {"log": {"entries": [
    {"request": {"method": "POST", "url": "https://api.example.com/v1/chat", "headers": []},
     "response": {"status": 200, "content": {"mimeType": "application/json"}}}
]}}
TRACE = {"target": "Acme IDE", "messages": [{"type": "send", "payload": {"hook": "objc_msgSend", "selector": "toolCall:"}}]}


def _campaign(root):
    c = Campaign("acme-ide", root=root)
    c.acquire(sha256="abc123", version="1.0")
    c.static(strings_text="SandboxPolicy\naccess_token")
    c.dynamic(capture=TRACE)
    c.protocol(har=HAR)
    c.features(text="feature.multi_agent_v2 experimental")
    return c


class TestCanonicalPhases:
    def test_phase_order_and_slugs(self):
        slugs = [p.slug for p in CANONICAL_PHASES]
        assert slugs == ["acquisition", "static", "behavior", "protocol", "threat-model", "features"]

    def test_numbers_zero_padded_and_sequential(self):
        nums = [p.number for p in CANONICAL_PHASES]
        assert nums == [1, 2, 3, 4, 5, 6]


class TestGenerate:
    def test_produces_a_doc_per_phase_plus_index(self, tmp_path):
        docs = generate_phase_docs("acme-ide", _campaign(tmp_path).graph)
        assert "00_index.md" in docs
        assert "01_acquisition.md" in docs
        assert "05_threat_model.md" in docs
        assert len([k for k in docs if k != "00_index.md"]) == len(CANONICAL_PHASES)

    def test_phase_docs_reference_relevant_nodes(self, tmp_path):
        docs = generate_phase_docs("acme-ide", _campaign(tmp_path).graph)
        assert "SandboxPolicy" in docs["02_static.md"]
        assert "api.example.com/v1/chat" in docs["04_protocol.md"]
        assert "objc_msgSend" in docs["03_behavior.md"]

    def test_index_links_each_phase(self, tmp_path):
        docs = generate_phase_docs("acme-ide", _campaign(tmp_path).graph)
        index = docs["00_index.md"]
        assert "01_acquisition.md" in index
        assert "06_features.md" in index

    def test_deterministic(self, tmp_path):
        a = generate_phase_docs("t", _campaign(tmp_path / "a").graph)
        b = generate_phase_docs("t", _campaign(tmp_path / "b").graph)
        assert a == b


class TestWrite:
    def test_writes_files_into_phases_dir(self, tmp_path):
        c = _campaign(tmp_path)
        paths = write_phase_docs("acme-ide", c.graph, root=tmp_path)
        assert any(p.name == "01_acquisition.md" for p in paths)
        phases_dir = tmp_path / "acme-ide" / "phases"
        assert phases_dir.is_dir()
        assert (phases_dir / "00_index.md").exists()
