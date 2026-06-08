"""
phases.py - phased campaign layout (Theme 3, P2).

Generates the ``re/<target>/phases/NN_Title.md`` work-product tree, following
the hermes-re convention (zero-padded numbered phase docs + a 00_index MOC).
Each phase doc is rendered from the relevant slice of the campaign graph, so
the human-readable narrative stays in lockstep with the content-addressed data.
Deterministic: same graph -> byte-identical docs.

Phase -> node-type mapping:
  01 acquisition   <- code-artifact
  02 static        <- binary-string, function-interest
  03 behavior      <- dynamic-trace, process-hook
  04 protocol      <- captured-request
  05 threat-model  <- risk            (full trees/matrix via threat_model.py)
  06 features      <- feature-flag
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

from .graph_schema import KnowledgeGraph


@dataclass(frozen=True)
class Phase:
    number: int
    slug: str
    title: str
    node_types: tuple


CANONICAL_PHASES: List[Phase] = [
    Phase(1, "acquisition", "Binary Acquisition & Provenance", ("code-artifact",)),
    Phase(2, "static", "Static Analysis & Disassembly", ("binary-string", "function-interest")),
    Phase(3, "behavior", "Dynamic Behavior & Instrumentation", ("dynamic-trace", "process-hook")),
    Phase(4, "protocol", "Protocol & Traffic Mapping", ("captured-request",)),
    Phase(5, "threat-model", "Attack Trees & Dual-Use", ("risk",)),
    Phase(6, "features", "Feature Flags & Codenames", ("feature-flag",)),
]


def _filename(phase: Phase) -> str:
    return f"{phase.number:02d}_{phase.slug.replace('-', '_')}.md"


def _nodes_for(graph: KnowledgeGraph, phase: Phase) -> List:
    return sorted(
        (n for n in graph.nodes.values() if n.type in phase.node_types),
        key=lambda n: (n.title, n.id),
    )


def _render_phase(target: str, phase: Phase, graph: KnowledgeGraph, generated_at: Optional[str]) -> str:
    nodes = _nodes_for(graph, phase)
    lines = [f"# Phase {phase.number:02d} — {phase.title}", ""]
    if generated_at:
        lines += [f"_Generated: {generated_at}_", ""]
    lines += [f"**Target:** {target}", f"**Artifacts in this phase:** {len(nodes)}", ""]

    if phase.slug == "threat-model":
        lines += [
            "## Risk Surfaces",
            "",
            "See `../threat-model/attack_tree.md` and `../threat-model/dual_use_matrix.md`"
            " for the full trees + dual-use mapping.",
            "",
        ]

    lines.append("## Findings")
    lines.append("")
    if not nodes:
        lines.append("_(no artifacts captured for this phase yet)_")
    else:
        for n in nodes:
            detail = ""
            if n.type == "captured-request":
                auth = ", ".join(json.loads(n.content).get("auth_schemes", [])) or "none"
                detail = f" — auth: {auth}"
            elif n.type == "binary-string":
                detail = f" — ctx: {json.loads(n.content).get('context', '')}"
            lines.append(f"- `{n.title}`{detail}")
    lines += ["", "---", f"_Auto-generated phase doc (pi_ide_re.phases) for {target}._", ""]
    return "\n".join(lines)


def _render_index(target: str, generated_at: Optional[str]) -> str:
    lines = [f"# RE Campaign — {target}", "", "## Phases", ""]
    if generated_at:
        lines = [f"# RE Campaign — {target}", "", f"_Generated: {generated_at}_", "", "## Phases", ""]
    for p in CANONICAL_PHASES:
        lines.append(f"{p.number}. [{p.title}]({_filename(p)})")
    lines += [
        "",
        "## Threat Model",
        "",
        "- [Attack Tree](../threat-model/attack_tree.md)",
        "- [Dual-Use Matrix](../threat-model/dual_use_matrix.md)",
        "",
    ]
    return "\n".join(lines)


def generate_phase_docs(target: str, graph: KnowledgeGraph, generated_at: Optional[str] = None) -> Dict[str, str]:
    docs: Dict[str, str] = {"00_index.md": _render_index(target, generated_at)}
    for phase in CANONICAL_PHASES:
        docs[_filename(phase)] = _render_phase(target, phase, graph, generated_at)
    return docs


def write_phase_docs(
    target: str, graph: KnowledgeGraph, root: Union[str, Path] = "re", generated_at: Optional[str] = None
) -> List[Path]:
    out_dir = Path(root).expanduser().resolve() / target / "phases"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for name, content in generate_phase_docs(target, graph, generated_at).items():
        path = out_dir / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return sorted(written)
