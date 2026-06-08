"""
feature_flags.py - feature-flag / internal-codename enumeration (Theme 2, P2).

Recipe from KikkaSkills/codex-re/FEATURE_FLAGS.md: dump debug-command / config
output and regex out the flags + codenames, grouped by lifecycle status. The
result is a ``FeatureFlagMap`` (status -> sorted flag names) plus content-
addressed ``feature-flag`` nodes that FINDINGS.md surfaces as internal codenames.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from ..graph_schema import FeatureFlag, GraphNode
from .base import StageResult

# dotted flags: feature.multi_agent_v2 ; SCREAMING flags/codenames: ENABLE_AGENT_MODE
_DOTTED = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\b")
_SCREAMING = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

_STATUS_KEYWORDS = [
    ("deprecated", "deprecated"),
    ("removed", "deprecated"),
    ("under development", "dev"),
    ("in development", "dev"),
    ("wip", "dev"),
    ("experimental", "experimental"),
    ("beta", "experimental"),
    ("stable", "stable"),
    ("ga", "stable"),
    ("enabled", "stable"),
]

STATUS_ORDER = ["stable", "experimental", "dev", "deprecated", "unknown"]


def _infer_status(line: str) -> str:
    low = line.lower()
    for keyword, status in _STATUS_KEYWORDS:
        if keyword in low:
            return status
    return "unknown"


class FeatureFlagStage:
    name = "feature-flags"

    def extract(self, text: str, source: str = "") -> StageResult:
        """Regex flags + codenames out of debug/config text."""
        found: Dict[str, FeatureFlag] = {}
        for line in text.splitlines():
            status = _infer_status(line)
            for pat in (_DOTTED, _SCREAMING):
                for name in pat.findall(line):
                    if name not in found:  # dedup by name, first sorted occurrence wins
                        found[name] = FeatureFlag(name=name, status=status, source=source)
        return self._assemble(found)

    def ingest(self, flags: List[Dict[str, Any]]) -> StageResult:
        found: Dict[str, FeatureFlag] = {}
        for f in flags:
            name = f.get("name")
            if not name or name in found:
                continue
            found[name] = FeatureFlag(
                name=name, status=f.get("status", "unknown"), value=f.get("value"), source=f.get("source", "")
            )
        return self._assemble(found)

    def ingest_file(self, path: Any) -> StageResult:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest(json.load(f))

    def _assemble(self, found: Dict[str, FeatureFlag]) -> StageResult:
        nodes: List[GraphNode] = [found[name].to_graph_node(source_page="(feature-flags)") for name in sorted(found)]
        return StageResult(stage=self.name, nodes=nodes, edges=[], summary={"flags": len(nodes)})


def feature_flag_map(result: StageResult) -> Dict[str, List[str]]:
    """Group the feature-flag nodes by status into a FeatureFlagMap."""
    fmap: Dict[str, List[str]] = {status: [] for status in STATUS_ORDER}
    for node in result.nodes:
        if node.type != "feature-flag":
            continue
        status = json.loads(node.content).get("status", "unknown")
        fmap.setdefault(status, []).append(node.title)
    return {status: sorted(names) for status, names in fmap.items()}
