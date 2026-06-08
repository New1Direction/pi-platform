"""
Tests for feature-flag enumeration (Theme 2, P2).

Recipe from codex-re/FEATURE_FLAGS.md: debug-command/config output + regex ->
flags/codenames grouped by status into a FeatureFlagMap. Deterministic:
extraction over the same text yields identical content-addressed nodes.
"""

from __future__ import annotations

from pi_ide_re.stages import feature_flags as ff

DEBUG_OUTPUT = """
ENABLE_AGENT_MODE        (stable)
feature.multi_agent_v2   experimental
codex.windsurf_beta      under development
LEGACY_TOOL_API          deprecated
just some prose with no flags at all
"""


class TestExtract:
    def test_finds_dotted_and_screaming_flags(self):
        result = ff.FeatureFlagStage().extract(DEBUG_OUTPUT)
        names = {n.title for n in result.nodes if n.type == "feature-flag"}
        assert "ENABLE_AGENT_MODE" in names
        assert "feature.multi_agent_v2" in names
        assert "codex.windsurf_beta" in names
        assert "LEGACY_TOOL_API" in names

    def test_ignores_prose(self):
        result = ff.FeatureFlagStage().extract("this is just prose, nothing here")
        assert [n for n in result.nodes if n.type == "feature-flag"] == []

    def test_status_inference(self):
        result = ff.FeatureFlagStage().extract(DEBUG_OUTPUT)
        fmap = ff.feature_flag_map(result)
        assert "ENABLE_AGENT_MODE" in fmap["stable"]
        assert "feature.multi_agent_v2" in fmap["experimental"]
        assert "codex.windsurf_beta" in fmap["dev"]
        assert "LEGACY_TOOL_API" in fmap["deprecated"]

    def test_deterministic(self):
        a = sorted(n.id for n in ff.FeatureFlagStage().extract(DEBUG_OUTPUT).nodes)
        b = sorted(n.id for n in ff.FeatureFlagStage().extract(DEBUG_OUTPUT).nodes)
        assert a == b

    def test_dedup_by_name(self):
        result = ff.FeatureFlagStage().extract("FOO_BAR_FLAG\nFOO_BAR_FLAG experimental")
        names = [n.title for n in result.nodes if n.type == "feature-flag"]
        assert names.count("FOO_BAR_FLAG") == 1


class TestIngestStructured:
    def test_structured_flags_grouped(self):
        flags = [
            {"name": "a.b", "status": "stable"},
            {"name": "c.d", "status": "experimental"},
        ]
        result = ff.FeatureFlagStage().ingest(flags)
        fmap = ff.feature_flag_map(result)
        assert fmap["stable"] == ["a.b"]
        assert fmap["experimental"] == ["c.d"]

    def test_map_groups_sorted(self):
        flags = [{"name": "z.flag", "status": "stable"}, {"name": "a.flag", "status": "stable"}]
        fmap = ff.feature_flag_map(ff.FeatureFlagStage().ingest(flags))
        assert fmap["stable"] == ["a.flag", "z.flag"]
