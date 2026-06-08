"""
Tests for the single labeled dispatcher on Campaign (Theme 4, P3).

Every phase transition routes through one auditable site (_dispatch), which
appends a transition-log entry carrying a running canonical state hash. This
makes a campaign trivially traceable/replayable (the Kabuki conversation_runtime
_dispatch discipline applied to RE campaigns). Deterministic: identical
campaigns produce identical transition logs.
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


def _run(root):
    c = Campaign("acme-ide", root=root)
    c.acquire(sha256="abc123")
    c.static(strings_text="SandboxPolicy")
    c.dynamic(capture=TRACE)
    c.protocol(har=HAR)
    c.features(text="feature.x experimental")
    return c


class TestDispatcher:
    def test_one_transition_per_phase_in_order(self, tmp_path):
        c = _run(tmp_path)
        assert [t["phase"] for t in c.transitions] == PHASES

    def test_transitions_are_sequential(self, tmp_path):
        c = _run(tmp_path)
        assert [t["seq"] for t in c.transitions] == list(range(1, len(PHASES) + 1))

    def test_each_transition_records_delta_and_state_hash(self, tmp_path):
        c = _run(tmp_path)
        for t in c.transitions:
            assert "nodes_added" in t and t["nodes_added"] >= 0
            assert t["state_hash"] and isinstance(t["state_hash"], str)

    def test_dispatcher_is_only_mutation_site(self, tmp_path):
        c = _run(tmp_path)
        # records and transitions stay in lockstep (every mutation went through _dispatch)
        assert len(c.transitions) == len(c.records)
        assert [t["phase"] for t in c.transitions] == [r.phase for r in c.records]

    def test_final_state_hash_matches_graph(self, tmp_path):
        c = _run(tmp_path)
        assert c.transitions[-1]["state_hash"] == c.state_hash()

    def test_transition_log_deterministic(self, tmp_path):
        a = _run(tmp_path / "a").transitions
        b = _run(tmp_path / "b").transitions
        assert a == b
