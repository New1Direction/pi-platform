"""
frida_templates.py - Electron/objc_msgSend Frida template library (Theme 1, P2).

Bundles parameterized .js instrumentation templates (under
``pi_ide_re/frida_templates/``) for Electron-based AI IDEs and generalizes the
cursor-re objc_msgSend selector-filter pattern (keywords: tool/agent/composer/
mcp/plugin) to Cursor / Windsurf / Antigravity / VSCode forks.

Rendering injects the selector keyword list deterministically (sorted + deduped
so order never changes the script). Each hook *configuration* (template +
selector) is emitted as a content-addressed ProcessHook node via
``plan_hooks()`` - the instrumentation plan is in the graph before any live
attach. The rendered script is then handed to
``DynamicTraceStage.capture(script_source=...)``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from ..graph_schema import ProcessHook
from .base import StageResult

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "frida_templates"

# Selector keywords that flag interesting Objective-C message sends in modern
# AI IDEs. Source: cursor-re frida-templates.
DEFAULT_SELECTORS: List[str] = ["agent", "composer", "mcp", "plugin", "tool"]

_TEMPLATES: Dict[str, str] = {
    "electron-objc-selector-filter": "electron-objc-selector-filter.js",
    "electron-multiprocess-io": "electron-multiprocess-io.js",
    "windows-ipc": "windows-ipc.js",
    "linux-ipc": "linux-ipc.js",
}

# Which templates apply on which host OS. objc_msgSend is macOS-only; the posix
# IO template covers macOS+Linux; the IPC variants are OS-specific.
PLATFORM_TEMPLATES: Dict[str, List[str]] = {
    "macos": ["electron-objc-selector-filter", "electron-multiprocess-io"],
    "linux": ["electron-multiprocess-io", "linux-ipc"],
    "windows": ["windows-ipc"],
}


def list_templates() -> List[str]:
    return sorted(_TEMPLATES)


def templates_for_platform(platform: str) -> List[str]:
    """Templates appropriate for a host OS ('macos' | 'linux' | 'windows')."""
    key = platform.lower()
    if key not in PLATFORM_TEMPLATES:
        raise ValueError(f"unknown platform '{platform}'. Known: {sorted(PLATFORM_TEMPLATES)}")
    return list(PLATFORM_TEMPLATES[key])


def _read_template(name: str) -> str:
    if name not in _TEMPLATES:
        raise KeyError(f"unknown frida template '{name}'. Known: {list_templates()}")
    return (_TEMPLATE_DIR / _TEMPLATES[name]).read_text(encoding="utf-8")


def load_template(name: str, selectors: Optional[List[str]] = None) -> str:
    """Load a template and inject the selector keyword list deterministically."""
    src = _read_template(name)
    sel = sorted(set(selectors if selectors is not None else DEFAULT_SELECTORS))
    return src.replace("__SELECTORS__", json.dumps(sel))


def render_objc_selector_filter(selectors: Optional[List[str]] = None) -> str:
    """Convenience: render the objc_msgSend selector filter."""
    return load_template("electron-objc-selector-filter", selectors)


def plan_hooks(template: str, selectors: Optional[List[str]] = None) -> StageResult:
    """Represent the instrumentation plan (template + each selector) as
    content-addressed ProcessHook nodes."""
    if template not in _TEMPLATES:
        raise KeyError(f"unknown frida template '{template}'. Known: {list_templates()}")
    sel = sorted(set(selectors if selectors is not None else DEFAULT_SELECTORS))
    nodes = [ProcessHook(template=template, selector=s).to_graph_node() for s in sel]
    return StageResult(
        stage="frida-template-plan",
        nodes=nodes,
        edges=[],
        summary={"template": template, "selectors": sel, "hooks": len(sel)},
    )
