"""
Tests for the prompt-marker injection technique (Theme 2, P3).

Technique: inject a unique sentinel marker into an input, then probe the system
about the text AROUND the marker (not the secret directly). The model tends to
echo the surrounding hidden structure (system prompt / memory / tool schema),
which we then recover by locating the marker in the response.

All helpers are deterministic and offline-testable.
"""

from __future__ import annotations

from pi_ide_re import prompt_marker as pm


class TestMarker:
    def test_marker_deterministic_per_seed(self):
        assert pm.make_marker("session-1") == pm.make_marker("session-1")

    def test_marker_unique_per_seed(self):
        assert pm.make_marker("a") != pm.make_marker("b")

    def test_marker_has_recognizable_sentinel(self):
        m = pm.make_marker("x")
        assert pm.SENTINEL_PREFIX in m
        assert pm.is_marker(m)


class TestInject:
    def test_inject_suffix_and_prefix(self):
        m = pm.make_marker("s")
        assert pm.inject("hello", m, position="suffix").endswith(m)
        assert pm.inject("hello", m, position="prefix").startswith(m)


class TestProbe:
    def test_probe_references_marker_and_asks_for_surroundings(self):
        m = pm.make_marker("s")
        probe = pm.build_probe(m)
        assert m in probe
        assert "before" in probe.lower() or "preceding" in probe.lower()


class TestExtractStructure:
    RESPONSE = "SYSTEM: you are a helpful IDE agent\nMEMORY: user prefers python\n{MARKER}\nUSER: hi there"

    def test_recovers_lines_around_marker(self):
        m = pm.make_marker("s")
        response = self.RESPONSE.format(MARKER=m)
        recovered = pm.extract_structure(response, m, context=2)
        assert recovered["found"] is True
        assert "SYSTEM: you are a helpful IDE agent" in recovered["before"]
        assert "USER: hi there" in recovered["after"]
        # the marker line itself is not part of the recovered structure
        assert all(m not in line for line in recovered["before"] + recovered["after"])

    def test_not_found(self):
        recovered = pm.extract_structure("no marker here", pm.make_marker("s"))
        assert recovered["found"] is False


class TestRecipe:
    def test_recipe_md_documents_technique(self):
        md = pm.recipe_md()
        assert "marker" in md.lower()
        assert "##" in md  # it's markdown with headings
