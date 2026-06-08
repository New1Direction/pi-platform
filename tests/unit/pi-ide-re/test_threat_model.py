"""
Tests for attack-tree + dual-use-matrix generation (Theme 3, P2).

Models hermes-re phase 05: a markdown attack tree (├──/└── branches rooted at
"compromise the target") and a 3-column dual-use matrix mapping each observed
technique to its offensive use and the DEFENSIVE pi-platform component that
counters it. Driven by graph node types; deterministic.
"""

from __future__ import annotations

from pi_ide_re.graph_schema import GraphNode, KnowledgeGraph, NodeMetadata
from pi_ide_re.stages import credential_flow as cf
from pi_ide_re.stages import feature_flags as ff
from pi_ide_re.stages import ghidra_static as gs
from pi_ide_re.stages import traffic_capture as tc
from pi_ide_re.threat_model import generate_attack_tree, generate_dual_use_matrix, write_threat_model

HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/v1/chat",
                    "headers": [{"name": "Authorization", "value": "x"}],
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            }
        ]
    }
}
CREDS = {
    "target": "acme-ide",
    "ssl_pinning_bypassed": True,
    "credentials": [{"source": "keychain", "key": "svc/access_token", "value": "S", "type": "oauth"}],
}


def _graph() -> KnowledgeGraph:
    g = KnowledgeGraph()
    tc.TrafficCaptureStage().ingest_har(HAR).add_to(g)
    cf.CredentialFlowStage().ingest(CREDS).add_to(g)
    gs.GhidraStaticStage().scan_strings("SandboxPolicy\nspawn_exec").add_to(g)
    ff.FeatureFlagStage().extract("feature.multi_agent_v2 experimental").add_to(g)
    return g


class TestAttackTree:
    def test_has_root_and_tree_branches(self):
        tree = generate_attack_tree("acme-ide", _graph())
        assert "Root:" in tree
        assert "acme-ide" in tree
        assert ("├──" in tree) or ("└──" in tree)

    def test_branches_reflect_present_categories(self):
        tree = generate_attack_tree("acme-ide", _graph())
        low = tree.lower()
        assert "protocol" in low  # captured-request present
        assert "credential" in low or "auth" in low  # credential/risk present
        assert "sandbox" in low  # sandbox binary-string present

    def test_deterministic(self):
        assert generate_attack_tree("t", _graph()) == generate_attack_tree("t", _graph())

    def test_empty_graph_still_valid(self):
        tree = generate_attack_tree("empty", KnowledgeGraph())
        assert "Root:" in tree


class TestDualUseMatrix:
    def test_is_table_with_three_columns(self):
        matrix = generate_dual_use_matrix("acme-ide", _graph())
        assert "| Technique" in matrix or "Technique" in matrix.split("\n")[0]
        # markdown table separator row
        assert "---" in matrix
        # offense + defense columns
        low = matrix.lower()
        assert "offensive" in low and "defensive" in low

    def test_maps_to_defensive_components(self):
        matrix = generate_dual_use_matrix("acme-ide", _graph())
        assert "pi_extension_governor" in matrix or "pi_micro_agents" in matrix

    def test_deterministic(self):
        assert generate_dual_use_matrix("t", _graph()) == generate_dual_use_matrix("t", _graph())


class TestRiskSurfaces:
    """Explicit risk nodes render with THEIR own offense/defense, not the generic auth bucket."""

    def _risk_graph(self):
        g = KnowledgeGraph()
        n = GraphNode(
            id="risk/x",
            type="risk",
            title="NemoClaw: sandbox-escape",
            content=(
                "OFFENSE: escapes the OpenShell pod via kernel bug\n"
                "DEFENSE (NemoClaw): Landlock + dropped caps\n"
                "PI-PLATFORM EQUIVALENT: pi_extension_governor fail-closed sandbox"
            ),
            metadata=NodeMetadata(source_page="x", tags=["risk", "sandbox-escape"]),
        )
        g.nodes[n.id] = n
        return g

    def test_attack_tree_uses_risk_own_offense_not_credential_text(self):
        tree = generate_attack_tree("t", self._risk_graph())
        assert "sandbox-escape" in tree
        assert "escapes the OpenShell pod" in tree  # its own offense
        assert "bypass SSL pinning" not in tree  # NOT the generic credential offense
        assert "Risk Surface" in tree  # dedicated branch

    def test_dual_use_matrix_includes_risk_with_defense(self):
        matrix = generate_dual_use_matrix("t", self._risk_graph())
        assert "sandbox-escape" in matrix
        assert "Landlock" in matrix
        assert "pi_extension_governor" in matrix


class TestWrite:
    def test_writes_both_files(self, tmp_path):
        paths = write_threat_model("acme-ide", _graph(), root=tmp_path)
        assert paths["attack_tree"].exists()
        assert paths["dual_use_matrix"].exists()
        assert (tmp_path / "acme-ide" / "threat-model").is_dir()
