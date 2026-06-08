"""
Tests for the ensemble determinism arbiter (Theme 4, P3 - INVESTIGATE ONLY).

A DETERMINISTIC, OFFLINE scaffold modeled on KikkaSkills/det_ensemble.py's
fast(generate)->strong(select) shape, framed for the parity-divergence use case:
when Python and Rust outputs disagree, deterministically select a canonical
result from a candidate pool via a pluggable scorer. No network/LLM calls - the
value is the pluggable framework, not a model.
"""

from __future__ import annotations

from pi_ide_re.det.ensemble import arbitrate, generate_candidates, select_best


class TestGenerate:
    def test_default_generator_deterministic_and_distinct(self):
        a = generate_candidates("seed", 4)
        b = generate_candidates("seed", 4)
        assert a == b
        assert len(set(a)) == 4

    def test_custom_generator_used(self):
        cands = generate_candidates("x", 3, generator=lambda s, n: [f"{s}-{i}" for i in range(n)])
        assert cands == ["x-0", "x-1", "x-2"]


class TestSelect:
    def test_select_best_by_scorer_min(self):
        out = select_best("orig", ["a", "bb", "ccc"], scorer=len)
        assert out["best"] == "a"
        assert out["ranked"][0] == "a"

    def test_default_scorer_deterministic(self):
        a = select_best("o", ["x", "y", "z"])
        b = select_best("o", ["x", "y", "z"])
        assert a == b
        assert a["best"] in ["x", "y", "z"]


class TestArbitrate:
    def test_agreement_is_not_divergence(self):
        out = arbitrate("same", "same")
        assert out["diverged"] is False
        assert out["winner"] == "same"

    def test_divergence_selects_deterministically(self):
        a = arbitrate("py_out", "rust_out")
        b = arbitrate("py_out", "rust_out")
        assert a["diverged"] is True
        assert a == b
        assert a["winner"] in ("py_out", "rust_out")

    def test_extra_candidates_considered(self):
        out = arbitrate("py", "rust", candidates=["third"], scorer=len)
        # 'py' (len 2) beats 'rust'(4) and 'third'(5)
        assert out["winner"] == "py"
        assert "third" in out["ranked"]
