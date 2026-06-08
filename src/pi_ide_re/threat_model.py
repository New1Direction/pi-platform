"""
threat_model.py - attack trees + dual-use matrix (Theme 3, P2).

Models hermes-re phase 05. From the campaign graph it derives:

* ``attack_tree.md`` - a markdown attack tree (├──/└── branches) rooted at
  "compromise/subvert the target", with one branch per observed finding
  category and the concrete findings as leaves.
* ``dual_use_matrix.md`` - a 3-column table mapping each observed technique to
  its offensive use (Red) and the DEFENSIVE pi-platform component that counters
  it (Blue) - turning RE findings into hardening requirements.

Each category is gated on evidence actually present in the graph, so the threat
model never overclaims. Deterministic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Union

from .graph_schema import GraphNode, KnowledgeGraph


@dataclass(frozen=True)
class Category:
    key: str
    branch_title: str
    offense: str
    defense: str  # defensive pi-platform component + control

    def matches(self, node: GraphNode) -> bool:
        return _CATEGORY_PREDICATES[self.key](node)


def _is_credential_trace(n: GraphNode) -> bool:
    # Only real credential dynamic-traces — NOT every risk node. Risk nodes are
    # explicit findings rendered in their own branch with their own offense.
    return n.type == "dynamic-trace" and "credential:" in n.title


def _risk_nodes(graph: "KnowledgeGraph") -> List[GraphNode]:
    return sorted((n for n in graph.nodes.values() if n.type == "risk"), key=lambda n: n.title)


def _parse_risk(node: GraphNode) -> tuple:
    """Pull (offense, defense, pi_equivalent) out of a risk node's content.

    Recognizes the ``OFFENSE:`` / ``DEFENSE...:`` / ``PI-...:`` convention; falls
    back to the first content line as the offense so any risk node renders.
    """
    offense, defense, pimap = "", "", ""
    for raw in node.content.splitlines():
        line = raw.strip()
        up = line.upper()
        if up.startswith("OFFENSE:"):
            offense = line.split(":", 1)[1].strip()
        elif up.startswith("DEFENSE"):
            defense = line.split(":", 1)[1].strip()
        elif up.startswith("PI-PLATFORM") or up.startswith("PI-MAP") or up.startswith("PI EQUIV"):
            pimap = line.split(":", 1)[1].strip()
    if not offense:
        offense = (node.content.splitlines()[0].strip() if node.content.strip() else node.title)[:140]
    return offense, defense, pimap


def _is_sandbox_string(n: GraphNode) -> bool:
    if n.type != "binary-string":
        return False
    ctx = json.loads(n.content).get("context", "").lower()
    return any(k in ctx for k in ("sandbox", "exec", "spawn", "policy", "seatbelt"))


_CATEGORY_PREDICATES: Dict[str, Callable[[GraphNode], bool]] = {
    "auth": _is_credential_trace,
    "protocol": lambda n: n.type == "captured-request",
    "instrumentation": lambda n: (
        n.type == "process-hook" or (n.type == "dynamic-trace" and "credential:" not in n.title)
    ),
    "sandbox": _is_sandbox_string,
    "features": lambda n: n.type == "feature-flag",
}

CATEGORIES: List[Category] = [
    Category(
        "protocol",
        "Protocol Surface Takeover",
        "Replay/forge API calls; harvest endpoints + auth headers via MITM",
        "pi_micro_agents API auditors (cors/http-method/mime) + auth_guard on console routes",
    ),
    Category(
        "auth",
        "Credential & Auth Surface",
        "Lift OAuth/session/API-key material from keychain/defaults; bypass SSL pinning",
        "pi_extension_governor secret-handling controls + fingerprint-only logging (never store values)",
    ),
    Category(
        "instrumentation",
        "Runtime Instrumentation & Tool Abuse",
        "Hook objc_msgSend/IPC to drive tool/agent/composer surfaces or inject calls",
        "pi_extension_governor sandbox (fail-closed) + inspector blocks introspection escapes",
    ),
    Category(
        "sandbox",
        "Sandbox / Execution Escape",
        "Reach spawn/exec or weaken sandbox policy strings to run host code",
        "pi_extension_governor fail-closed subprocess sandbox + AST inspector",
    ),
    Category(
        "features",
        "Hidden Feature / Flag Abuse",
        "Flip experimental/dev flags to unlock ungated behavior",
        "governance flag gating + objective_tracker scope guards",
    ),
]


def _present(graph: KnowledgeGraph) -> List[Category]:
    return [c for c in CATEGORIES if any(c.matches(n) for n in graph.nodes.values())]


def _leaves(graph: KnowledgeGraph, cat: Category, limit: int = 8) -> List[str]:
    titles = sorted({n.title for n in graph.nodes.values() if cat.matches(n)})
    return titles[:limit]


def generate_attack_tree(target: str, graph: KnowledgeGraph) -> str:
    # Build sections: keyword-derived categories, then explicit risk surfaces.
    sections: List[tuple] = []  # (branch_title, [(leaf, offense), ...])
    for cat in _present(graph):
        leaves = [(t, cat.offense) for t in _leaves(graph, cat)]
        if leaves:
            sections.append((cat.branch_title, leaves))
    risks = _risk_nodes(graph)
    if risks:
        sections.append(("Identified Risk Surfaces", [(n.title, _parse_risk(n)[0]) for n in risks]))

    lines = [f"# Attack Tree — {target}", "", "```", f"Root: Compromise or Subvert {target}"]
    if not sections:
        lines.append("└── (no findings captured yet — run the capture stages)")
    else:
        for i, (title, leaves) in enumerate(sections):
            last = i == len(sections) - 1
            bstem = "└──" if last else "├──"
            cont = "    " if last else "│   "
            lines.append(f"{bstem} {i + 1}. {title}")
            for j, (leaf, off) in enumerate(leaves):
                lstem = "└──" if j == len(leaves) - 1 else "├──"
                lines.append(f"{cont}{lstem} {i + 1}.{j + 1} `{leaf}` → {off}")
    lines += ["```", "", "---", "_Auto-generated by pi_ide_re.threat_model._", ""]
    return "\n".join(lines)


def generate_dual_use_matrix(target: str, graph: KnowledgeGraph) -> str:
    present = _present(graph)
    lines = [
        f"# Dual-Use Matrix — {target}",
        "",
        "| Technique Observed | Offensive Use (Red) | Defensive Pattern (Blue → pi-platform) |",
        "| --- | --- | --- |",
    ]
    risks = _risk_nodes(graph)
    if not present and not risks:
        lines.append("| _(none yet)_ | — | — |")
    else:
        for cat in present:
            lines.append(f"| {cat.branch_title} | {cat.offense} | {cat.defense} |")
        for n in risks:
            off, deff, pimap = _parse_risk(n)
            defense = " → ".join(x for x in (deff, pimap) if x) or "—"
            lines.append(f"| {n.title} | {off} | {defense} |")
    lines += ["", "---", "_Each finding maps to a defensive control. Drive these into the hardening backlog._", ""]
    return "\n".join(lines)


def write_threat_model(target: str, graph: KnowledgeGraph, root: Union[str, Path] = "re") -> Dict[str, Path]:
    out_dir = Path(root).expanduser().resolve() / target / "threat-model"
    out_dir.mkdir(parents=True, exist_ok=True)
    tree_path = out_dir / "attack_tree.md"
    matrix_path = out_dir / "dual_use_matrix.md"
    tree_path.write_text(generate_attack_tree(target, graph), encoding="utf-8")
    matrix_path.write_text(generate_dual_use_matrix(target, graph), encoding="utf-8")
    return {"attack_tree": tree_path, "dual_use_matrix": matrix_path}
