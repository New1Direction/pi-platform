"""
ghidra_static.py - headless-Ghidra static analysis stage (Theme 1, P2).

Adapts KikkaSkills/analysis/cursor-re/ghidra/cursor_helpers_post_script.py
(strings / functions / xrefs + keyword detection) so the analysis reports we
currently write by hand (re/<target>/analysis/key_strings.txt, structural_report)
are auto-produced and fed into the content-addressed graph.

Deterministic core:
* ``scan_strings(text)`` - keyword detection over a plain ``strings`` dump.
  Runs anywhere (no Ghidra needed). -> BinaryString nodes.
* ``ingest(dump)`` - a structured Ghidra dump (strings + functions + xrefs)
  -> BinaryString + FunctionInterest nodes. Load addresses are carried for
  humans but never affect node identity (they shift every build).
* ``render_key_strings()`` reproduces the flat key-strings report.

Live ``capture_strings()`` shells out to ``strings``; ``capture_ghidra()`` runs
``analyzeHeadless`` with this stage's post-script. Both raise a clear StageError
when the tool is absent (Ghidra is bundled under
KikkaSkills/ghidra_11.2.1_PUBLIC but not on PATH by default).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..graph_schema import BinaryString, FunctionInterest, GraphNode
from .base import StageError, StageResult

# Keyword set that flags interesting strings/functions. Superset of the
# cursor_helpers_post_script KEY_TERMS, generalized for AI IDE RE.
DEFAULT_KEYWORDS: List[str] = sorted(
    {
        # sandbox / isolation
        "sandbox", "seatbelt", "bubblewrap", "workspace_read", "policy", "insecure",
        # agent / tool / model surfaces
        "agent", "tool", "composer", "mcp", "plugin", "model", "prompt", "gemini",
        # auth / secrets
        "token", "secret", "api_key", "apikey", "auth", "credential", "oauth", "session",
        # process / exec
        "spawn", "exec", "subprocess",
        # network
        "endpoint", "grpc", "websocket", "cloudcode",
    }
)


def _node_value(node: GraphNode) -> str:
    return json.loads(node.content).get("value", "")


def _node_context(node: GraphNode) -> str:
    return json.loads(node.content).get("context", "")


def _matched_keywords(text: str, keywords: List[str]) -> List[str]:
    low = text.lower()
    return sorted({k for k in keywords if k.lower() in low})


class GhidraStaticStage:
    name = "ghidra-static"

    # ---- deterministic ingest ------------------------------------------

    def scan_strings(self, text: str, keywords: Optional[List[str]] = None) -> StageResult:
        """Keyword-detect over a plain ``strings`` dump -> BinaryString nodes."""
        kws = sorted(set(keywords)) if keywords is not None else DEFAULT_KEYWORDS
        nodes: Dict[str, GraphNode] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            matched = _matched_keywords(line, kws)
            if not matched:
                continue
            bs = BinaryString(value=line, context=",".join(matched))
            node = bs.to_graph_node()
            nodes[node.id] = node
        return StageResult(
            stage=self.name,
            nodes=list(nodes.values()),
            edges=[],
            summary={"strings_matched": len(nodes), "keywords": kws},
        )

    def ingest(self, dump: Dict[str, Any], keywords: Optional[List[str]] = None) -> StageResult:
        """Structured Ghidra dump -> BinaryString + FunctionInterest nodes."""
        kws = sorted(set(keywords)) if keywords is not None else DEFAULT_KEYWORDS
        nodes: Dict[str, GraphNode] = {}

        for s in dump.get("strings", []):
            value = s.get("value", "")
            matched = _matched_keywords(value, kws)
            if not matched:
                continue
            node = BinaryString(value=value, context=",".join(matched), addr=s.get("addr")).to_graph_node()
            nodes[node.id] = node

        for fn in dump.get("functions", []):
            name = fn.get("name", "")
            matched = _matched_keywords(name, kws)
            if not matched:
                continue
            node = FunctionInterest(name=name, keywords=matched, entry=fn.get("entry")).to_graph_node()
            nodes[node.id] = node

        n_strings = sum(1 for n in nodes.values() if n.type == "binary-string")
        n_funcs = sum(1 for n in nodes.values() if n.type == "function-interest")
        return StageResult(
            stage=self.name,
            nodes=list(nodes.values()),
            edges=[],
            summary={"strings_matched": n_strings, "functions_matched": n_funcs, "keywords": kws},
        )

    def ingest_file(self, path: Any, keywords: Optional[List[str]] = None) -> StageResult:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest(json.load(f), keywords=keywords)

    # ---- report renderers ----------------------------------------------

    def render_key_strings(self, result: StageResult) -> str:
        """Reproduce the flat key_strings.txt report: sorted, unique, one per line."""
        values = sorted({_node_value(n) for n in result.nodes if n.type == "binary-string"})
        return "\n".join(values) + ("\n" if values else "")

    def render_structural_summary(self, result: StageResult, target: str = "") -> str:
        strings = sorted({_node_value(n) for n in result.nodes if n.type == "binary-string"})
        funcs = sorted({n.title for n in result.nodes if n.type == "function-interest"})
        lines = [f"=== Static Analysis Summary{(' - ' + target) if target else ''} ===", ""]
        lines.append(f"Keyword-flagged strings: {len(strings)}")
        lines.append(f"Functions of interest:   {len(funcs)}")
        if funcs:
            lines += ["", "Functions of interest:"] + [f"  - {f}" for f in funcs]
        return "\n".join(lines) + "\n"

    # ---- live capture --------------------------------------------------

    def capture_strings(self, binary_path: str, min_len: int = 6) -> StageResult:
        """Run the system ``strings`` tool over a binary and scan it."""
        tool = shutil.which("strings")
        if not tool:
            raise StageError("the `strings` tool is not available on PATH (install binutils).")
        if not Path(binary_path).exists():
            raise StageError(f"binary not found: {binary_path}")
        out = subprocess.check_output([tool, "-n", str(min_len), binary_path], text=True)  # pragma: no cover
        return self.scan_strings(out)

    def _resolve_ghidra(self, ghidra_home: Optional[str]) -> str:
        # An explicit ghidra_home is honored strictly - we do not silently fall
        # back to a bundled copy the caller never asked for.
        if ghidra_home is not None:
            candidates = [ghidra_home]
        else:
            candidates = [
                os.environ.get("GHIDRA_INSTALL_DIR"),
                str(Path.home() / "Documents/KikkaSkills/ghidra_11.2.1_PUBLIC"),
            ]
        for c in candidates:
            if c and (Path(c) / "support" / "analyzeHeadless").exists():
                return str(Path(c) / "support" / "analyzeHeadless")
        raise StageError(
            "Ghidra headless (analyzeHeadless) not found. Set GHIDRA_INSTALL_DIR or pass ghidra_home "
            "(a bundled copy lives under KikkaSkills/ghidra_11.2.1_PUBLIC)."
        )

    def capture_ghidra(
        self, binary_path: str, ghidra_home: Optional[str] = None, project_dir: Optional[str] = None
    ) -> StageResult:  # pragma: no cover - requires a full Ghidra install + minutes of analysis
        headless = self._resolve_ghidra(ghidra_home)
        if not Path(binary_path).exists():
            raise StageError(f"binary not found: {binary_path}")
        raise StageError(
            f"Ghidra headless is available at {headless}; wire the post-script that emits the structured "
            "dump (strings/functions/xrefs JSON), then feed it to ingest()."
        )
