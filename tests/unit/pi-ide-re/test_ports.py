"""
Tests for the "port" pipeline (Theme 3, P2).

A port turns an RE finding into a reusable defensive component: a SKILL.md
(frontmatter + Core Ideas / When to Use / Procedure / Integration / Attack
Surface) + a minimal runnable adapter + a registry entry. Modeled on
hermes-re/ports/*. Deterministic SKILL.md; adapter must be valid Python.
"""

from __future__ import annotations

import json

from pi_ide_re.graph_schema import CapturedRequest
from pi_ide_re.ports import Port, PortRegistry, generate_port, port_from_node, render_adapter, render_skill_md


def _sample_port() -> Port:
    node = CapturedRequest(
        method="POST", url="https://api.example.com/v1/chat", host="api.example.com",
        path="/v1/chat", auth_schemes=["authorization"]
    ).to_graph_node()
    return port_from_node(node, target="acme-ide")


class TestPortFromNode:
    def test_infers_name_and_source(self):
        port = _sample_port()
        assert port.slug().endswith("-port")
        assert "acme-ide" in port.slug()
        assert port.source  # originating finding recorded
        assert port.integration  # wired into pi components

    def test_unknown_type_still_yields_port(self):
        from pi_ide_re.graph_schema import GraphNode
        node = GraphNode(id="insight/x", type="insight", title="some insight", content="c")
        port = port_from_node(node, target="t")
        assert port.slug().endswith("-port")


class TestRenderSkill:
    def test_has_frontmatter_and_canonical_sections(self):
        md = render_skill_md(_sample_port())
        assert md.startswith("---")  # YAML frontmatter
        for section in ["Core Ideas Ported", "When to Use", "Procedure", "Integration", "Attack Surface"]:
            assert section in md

    def test_deterministic(self):
        assert render_skill_md(_sample_port()) == render_skill_md(_sample_port())


class TestRenderAdapter:
    def test_adapter_is_valid_python_with_run(self):
        src = render_adapter(_sample_port())
        compile(src, "<adapter>", "exec")  # must parse
        assert "def run(" in src
        assert "class " in src


class TestRegistryAndGenerate:
    def test_generate_writes_skill_adapter_and_registers(self, tmp_path):
        port = _sample_port()
        paths = generate_port(port, root=tmp_path)
        assert paths["skill"].exists() and paths["adapter"].exists()
        assert paths["skill"].name == "SKILL.md"
        # index.json updated
        reg = PortRegistry(root=tmp_path)
        assert port.slug() in reg.list_ports()

    def test_registry_persists_and_is_idempotent(self, tmp_path):
        port = _sample_port()
        generate_port(port, root=tmp_path)
        generate_port(port, root=tmp_path)  # twice
        reg = PortRegistry(root=tmp_path)
        index = json.loads(reg.index_path.read_text())
        assert list(index["ports"]).count(port.slug()) <= 1  # no dup keys
        assert port.slug() in index["ports"]
