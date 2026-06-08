"""
Tests for the marker-based checkpoint codec (Theme 4, P2).

Kabuki-style inline state markers (pack_state/unpack_state with a sentinel),
plus campaign pack/restore for pause/resume/replay. A content hash over the
state detects tampering on restore. Complements the platform's SQLite
ChainCheckpoint (orchestrator/checkpoint.py) - this is the portable inline form.
Deterministic: same campaign -> identical packed bytes.
"""

from __future__ import annotations

import json

import pytest

from pi_ide_re.det.checkpoint_codec import (
    MARKER,
    CheckpointMismatch,
    is_checkpoint_marker,
    pack_campaign,
    pack_state,
    restore_campaign,
    unpack_state,
)
from pi_ide_re.playbook import Campaign

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


def _campaign(root):
    c = Campaign("acme-ide", root=root)
    c.acquire(sha256="abc123")
    c.static(strings_text="SandboxPolicy")
    c.protocol(har=HAR)
    return c


class TestStateMarkers:
    def test_pack_unpack_round_trip(self):
        packed = pack_state({"a": 1, "b": [3, 2, 1]})
        assert MARKER in packed
        assert is_checkpoint_marker(packed)
        assert unpack_state(packed) == {"a": 1, "b": [3, 2, 1]}

    def test_non_marker_returns_none(self):
        assert is_checkpoint_marker("just some text") is False
        assert unpack_state("just some text") is None

    def test_pack_is_deterministic(self):
        assert pack_state({"a": 1, "b": 2}) == pack_state({"b": 2, "a": 1})

    def test_tampered_state_hash_raises(self):
        packed = pack_state({"x": 1})
        doc = json.loads(packed)
        doc["state"]["x"] = 999  # tamper without updating the hash
        with pytest.raises(CheckpointMismatch):
            unpack_state(json.dumps(doc))


class TestCampaignCheckpoint:
    def test_pack_campaign_deterministic(self, tmp_path):
        a = pack_campaign(_campaign(tmp_path / "a"))
        b = pack_campaign(_campaign(tmp_path / "b"))
        assert a == b

    def test_restore_round_trips_graph_and_records(self, tmp_path):
        c = _campaign(tmp_path)
        packed = pack_campaign(c)
        restored = restore_campaign(packed, root=tmp_path)
        assert restored.target == c.target
        assert sorted(restored.graph.nodes.keys()) == sorted(c.graph.nodes.keys())
        assert [r.phase for r in restored.records] == [r.phase for r in c.records]

    def test_resume_then_continue(self, tmp_path):
        c = _campaign(tmp_path)
        restored = restore_campaign(pack_campaign(c), root=tmp_path)
        # continue the campaign after resume
        restored.features(text="feature.x experimental")
        assert any(n.type == "feature-flag" for n in restored.graph.nodes.values())

    def test_restore_preserves_transition_log_and_seq(self, tmp_path):
        c = _campaign(tmp_path)
        restored = restore_campaign(pack_campaign(c), root=tmp_path)
        # the dispatcher audit trail survives pause/resume
        assert [t["phase"] for t in restored.transitions] == [t["phase"] for t in c.transitions]
        # and the seq counter continues rather than resetting
        restored.features(text="feature.x experimental")
        assert restored.transitions[-1]["seq"] == len(c.transitions) + 1

    def test_replay_equivalence(self, tmp_path):
        # a fresh run + a restored run produce the same node set (replay-safe)
        c1 = _campaign(tmp_path / "1")
        c2 = restore_campaign(pack_campaign(_campaign(tmp_path / "2")), root=tmp_path / "2")
        assert sorted(c1.graph.nodes.keys()) == sorted(c2.graph.nodes.keys())
