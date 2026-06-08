"""
Tests for deterministic memory tiering (Theme 4, P3).

Three tiers (KikkaSkills deterministic/ model):
  core      - immutable, human-authored (version-controlled)
  working   - candidates the agent appends freely
  promoted  - promoted only after >=N supporting validations or explicit approval

Invariant: ONLY core + promoted feed the canonical state hash. Churn in the
working tier must never change the canonical hash, so the stable state stays
reproducible while learning continues.
"""

from __future__ import annotations

import pytest

from pi_ide_re.det.memory_tiers import TieredMemory


class TestTiers:
    def test_core_is_seeded_and_in_canonical_hash(self):
        m = TieredMemory(core={"rule.no_wallclock_in_hash": True})
        assert "rule.no_wallclock_in_hash" in m.core_items()
        h = m.canonical_hash()
        m2 = TieredMemory(core={"rule.no_wallclock_in_hash": True})
        assert m2.canonical_hash() == h

    def test_candidate_does_not_change_canonical_hash(self):
        m = TieredMemory(core={"a": 1})
        before = m.canonical_hash()
        m.add_candidate("cand.x", "maybe")
        assert "cand.x" in m.working_items()
        assert "cand.x" not in m.promoted_items()
        assert m.canonical_hash() == before  # working churn is invisible to canonical state

    def test_promotion_after_threshold_changes_hash(self):
        m = TieredMemory(core={"a": 1}, threshold=3)
        before = m.canonical_hash()
        m.add_candidate("cand.x", "v")
        m.validate("cand.x")
        m.validate("cand.x")
        assert "cand.x" not in m.promoted_items()  # only 2 validations
        assert m.canonical_hash() == before
        m.validate("cand.x")  # 3rd -> auto-promote
        assert "cand.x" in m.promoted_items()
        assert "cand.x" not in m.working_items()
        assert m.canonical_hash() != before

    def test_explicit_approval_promotes_immediately(self):
        m = TieredMemory(threshold=5)
        m.add_candidate("cand.y", "v")
        m.approve("cand.y")
        assert "cand.y" in m.promoted_items()

    def test_core_is_immutable_via_api(self):
        m = TieredMemory(core={"a": 1})
        with pytest.raises(Exception):
            m.add_candidate("a", 2)  # cannot shadow/overwrite a core key

    def test_validate_unknown_raises(self):
        m = TieredMemory()
        with pytest.raises(KeyError):
            m.validate("nope")

    def test_canonical_hash_includes_core_and_promoted_only(self):
        m = TieredMemory(core={"a": 1}, threshold=1)
        m.add_candidate("b", 2)
        m.validate("b")  # promote
        m.add_candidate("c", 3)  # stays working
        # hash depends on a + b (promoted), not c
        h_with_c = m.canonical_hash()
        m.add_candidate("d", 4)  # more working churn
        assert m.canonical_hash() == h_with_c
