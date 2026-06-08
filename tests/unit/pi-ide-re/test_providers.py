"""
Tests for the RE target provider pattern (Theme 3, P3).

Each target (antigravity-ide, orbstack, ...) is a provider exposing
binary/behavior/patch behind a thread-safe registry + single dispatch site.
"""

from __future__ import annotations

import threading

import pytest

from pi_ide_re.providers import ProviderNotFound, ProviderRegistry, TargetProvider


class DummyProvider(TargetProvider):
    target = "acme-ide"

    def acquire(self):
        return {"op": "acquire", "target": self.target, "sha256": "abc"}

    def behavior(self):
        return {"op": "behavior", "hooks": 1}

    def patch(self):
        return {"op": "patch", "applied": True}


class TestRegistry:
    def test_register_get_list(self):
        reg = ProviderRegistry()
        reg.register(DummyProvider())
        assert "acme-ide" in reg.list_targets()
        assert isinstance(reg.get("acme-ide"), DummyProvider)

    def test_unknown_provider_raises(self):
        reg = ProviderRegistry()
        with pytest.raises(ProviderNotFound):
            reg.get("nope")

    def test_dispatch_routes_to_op(self):
        reg = ProviderRegistry()
        reg.register(DummyProvider())
        assert reg.dispatch("acme-ide", "acquire")["sha256"] == "abc"
        assert reg.dispatch("acme-ide", "behavior")["hooks"] == 1
        assert reg.dispatch("acme-ide", "patch")["applied"] is True

    def test_dispatch_invalid_op_rejected(self):
        reg = ProviderRegistry()
        reg.register(DummyProvider())
        with pytest.raises(ValueError):
            reg.dispatch("acme-ide", "delete_everything")

    def test_register_is_idempotent_overwrite(self):
        reg = ProviderRegistry()
        reg.register(DummyProvider())
        reg.register(DummyProvider())
        assert reg.list_targets().count("acme-ide") == 1

    def test_thread_safe_registration(self):
        reg = ProviderRegistry()

        class P(TargetProvider):
            def __init__(self, name):
                self.target = name

            def acquire(self):
                return {}

            def behavior(self):
                return {}

            def patch(self):
                return {}

        def worker(i):
            reg.register(P(f"t{i}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(reg.list_targets()) == 20
