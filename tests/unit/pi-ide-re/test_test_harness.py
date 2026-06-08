"""
Tests for the RE test-harness helpers (Theme 1, P3).

Per-target isolation + a SQLite capture DB + deterministic snapshots, modeled on
agmsg_test_utils.py (load/reset env, capture DB query, snapshot). The capture DB
is content-addressed (idempotent record); queries are deterministically ordered;
workspaces are isolated per target so parallel campaigns can't collide.
"""

from __future__ import annotations

from pi_ide_re.test_harness import CampaignWorkspace, CaptureDB


class TestCaptureDB:
    def test_record_and_query_round_trip(self):
        db = CaptureDB(":memory:")
        db.record(phase="static", agent="ghidra", kind="string", key="SandboxPolicy", value="0x1000")
        rows = db.query()
        assert len(rows) == 1
        assert rows[0]["key"] == "SandboxPolicy"

    def test_record_is_idempotent_by_content(self):
        db = CaptureDB(":memory:")
        db.record(phase="p", agent="a", kind="k", key="x", value="v", captured_at="T1")
        db.record(phase="p", agent="a", kind="k", key="x", value="v", captured_at="T2")  # same content
        assert db.count() == 1

    def test_filter_by_phase_agent_kind(self):
        db = CaptureDB(":memory:")
        db.record(phase="static", agent="ghidra", kind="string", key="a", value="1")
        db.record(phase="protocol", agent="mitm", kind="request", key="b", value="2")
        assert len(db.query(phase="static")) == 1
        assert len(db.query(agent="mitm")) == 1
        assert len(db.query(kind="string")) == 1
        assert len(db.query(phase="nope")) == 0

    def test_query_deterministically_ordered(self):
        db = CaptureDB(":memory:")
        for k in ["z", "a", "m"]:
            db.record(phase="p", agent="a", kind="k", key=k, value="v")
        keys = [r["key"] for r in db.query()]
        assert keys == sorted(keys)

    def test_reset_clears(self):
        db = CaptureDB(":memory:")
        db.record(phase="p", agent="a", kind="k", key="x", value="v")
        db.reset()
        assert db.count() == 0


class TestCampaignWorkspace:
    def test_ensure_creates_standard_subdirs(self, tmp_path):
        ws = CampaignWorkspace(root=tmp_path, target="acme-ide")
        ws.ensure()
        for sub in ["payloads", "phases", "threat-model", "ports", "logs"]:
            assert (ws.target_dir / sub).is_dir()

    def test_reset_wipes_only_this_target(self, tmp_path):
        a = CampaignWorkspace(root=tmp_path, target="a")
        b = CampaignWorkspace(root=tmp_path, target="b")
        a.ensure()
        b.ensure()
        (b.target_dir / "logs" / "keep.txt").write_text("keep")
        a.reset()
        assert not a.target_dir.exists()
        assert (b.target_dir / "logs" / "keep.txt").exists()  # sibling untouched

    def test_snapshot_is_deterministic(self, tmp_path):
        def build(root):
            ws = CampaignWorkspace(root=root, target="acme-ide")
            ws.ensure()
            (ws.target_dir / "phases" / "01_acquisition.md").write_text("x")
            ws.db.record(phase="static", agent="a", kind="string", key="k", value="v")
            return ws.snapshot()

        assert build(tmp_path / "1") == build(tmp_path / "2")

    def test_snapshot_reports_files_and_capture_count(self, tmp_path):
        ws = CampaignWorkspace(root=tmp_path, target="acme-ide")
        ws.ensure()
        (ws.target_dir / "phases" / "01_acquisition.md").write_text("x")
        ws.db.record(phase="static", agent="a", kind="string", key="k", value="v")
        snap = ws.snapshot()
        assert snap["captures"] == 1
        assert any("01_acquisition.md" in f for f in snap["files"])
