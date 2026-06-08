"""
Tests for the Electron/objc_msgSend Frida template library (Theme 1, P2).

Templates are bundled .js with placeholders; rendering injects a selector
keyword list deterministically. Each hook *configuration* (template + selector)
is represented as a content-addressed ProcessHook node so the instrumentation
plan lives in the graph before any live attach.
"""

from __future__ import annotations

import pytest

from pi_ide_re.stages import frida_templates as ft


class TestTemplateLibrary:
    def test_lists_known_templates(self):
        names = ft.list_templates()
        assert "electron-objc-selector-filter" in names
        assert "electron-multiprocess-io" in names

    def test_default_selectors_cover_ide_keywords(self):
        assert {"tool", "agent", "composer", "mcp", "plugin"}.issubset(set(ft.DEFAULT_SELECTORS))

    def test_render_injects_selectors_and_is_deterministic(self):
        a = ft.render_objc_selector_filter(["tool", "agent"])
        b = ft.render_objc_selector_filter(["tool", "agent"])
        assert a == b
        assert "objc_msgSend" in a
        assert "tool" in a and "agent" in a
        # placeholder must be gone
        assert "__SELECTORS__" not in a

    def test_render_selector_order_normalized(self):
        # selector order should not change the rendered script (sorted+deduped)
        a = ft.render_objc_selector_filter(["agent", "tool", "tool"])
        b = ft.render_objc_selector_filter(["tool", "agent"])
        assert a == b

    def test_load_unknown_template_raises(self):
        with pytest.raises(KeyError):
            ft.load_template("does-not-exist")


class TestPlatformVariants:
    def test_windows_and_linux_templates_registered(self):
        names = ft.list_templates()
        assert "windows-ipc" in names
        assert "linux-ipc" in names

    def test_templates_for_platform(self):
        assert "electron-objc-selector-filter" in ft.templates_for_platform("macos")
        assert "linux-ipc" in ft.templates_for_platform("linux")
        assert "windows-ipc" in ft.templates_for_platform("windows")
        # macOS objc filter is not offered for windows
        assert "electron-objc-selector-filter" not in ft.templates_for_platform("windows")

    def test_unknown_platform_raises(self):
        with pytest.raises(ValueError):
            ft.templates_for_platform("solaris")

    def test_windows_template_hooks_windows_apis(self):
        src = ft.load_template("windows-ipc")
        assert ("WriteFile" in src) or ("WSASend" in src)
        assert "__SELECTORS__" not in src  # placeholder substituted even if unused

    def test_linux_template_hooks_socket_calls(self):
        src = ft.load_template("linux-ipc")
        assert ("sendmsg" in src) or ("recvmsg" in src) or ("connect" in src)

    def test_platform_variant_render_deterministic(self):
        assert ft.load_template("windows-ipc") == ft.load_template("windows-ipc")

    def test_plan_hooks_works_for_platform_variant(self):
        result = ft.plan_hooks("linux-ipc", ["sendmsg", "recvmsg"])
        assert len([n for n in result.nodes if n.type == "process-hook"]) == 2


class TestProcessHookPlan:
    def test_plan_hooks_makes_one_node_per_selector(self):
        result = ft.plan_hooks("electron-objc-selector-filter", ["tool", "mcp"])
        hook_nodes = [n for n in result.nodes if n.type == "process-hook"]
        assert len(hook_nodes) == 2

    def test_plan_is_content_addressed_and_stable(self):
        a = sorted(n.id for n in ft.plan_hooks("electron-objc-selector-filter", ["tool", "mcp"]).nodes)
        b = sorted(n.id for n in ft.plan_hooks("electron-objc-selector-filter", ["mcp", "tool"]).nodes)
        assert a == b

    def test_plan_summary_reports_template_and_selectors(self):
        result = ft.plan_hooks("electron-objc-selector-filter", ["tool"])
        assert result.summary["template"] == "electron-objc-selector-filter"
        assert result.summary["selectors"] == ["tool"]
