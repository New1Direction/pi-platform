"""
methodology.py - canonical FINDINGS.md / METHOD.md generation (Theme 2, P1).

Turns a campaign's content-addressed KnowledgeGraph into the two standard
teardown documents (templates: KikkaSkills/claude-code-re/{FINDINGS,METHOD}.md):

* FINDINGS.md - what was learned, organized into canonical sections (executive
  summary, API surfaces, payloads, internal codenames, tool schema, memory/
  state, still-unextracted). Driven by node types: captured-request -> API
  surfaces; feature-flag + binary-string -> internal codenames; dynamic-trace +
  process-hook -> tool schema.
* METHOD.md - the exact reproduction recipe (tools, the 5-phase playbook, the
  ordered steps, key lessons).

Both are DETERMINISTIC: same graph -> byte-identical markdown. No wall-clock is
read internally; pass ``generated_at`` if you want a date in the header.
(The roadmap pencilled this into exporter.py; a dedicated module keeps the
graph-driven doc logic separate from the Obsidian session-note writer.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from .graph_schema import KnowledgeGraph

CANONICAL_FINDINGS_SECTIONS = [
    "Executive Summary",
    "API Surfaces",
    "Completion / Payload Structure",
    "Internal Codenames",
    "Tool Schema",
    "Memory & State",
    "Still Unextracted",
]

# The repeatable five-phase teardown playbook (Theme 2, P2 - referenced here so
# METHOD.md always documents it; the typed stages live in playbook.py).
FIVE_PHASES = [
    ("acquisition", "Acquire the binary / app bundle and record provenance (hash, size, version)."),
    ("static", "Static analysis: strings, functions, xrefs, keyword detection (Ghidra/strings)."),
    ("dynamic-capture", "Live capture: Frida hooks + mitmproxy traffic against the running target."),
    ("protocol-mapping", "Map the protocol: endpoints, auth schemes, WebSocket frames, payload shapes."),
    ("feature-extraction", "Extract feature flags / codenames / tool schema and the memory-state model."),
]


def _by_type(graph: KnowledgeGraph, node_type: str) -> List:
    return sorted((n for n in graph.nodes.values() if n.type == node_type), key=lambda n: (n.title, n.id))


def _bullet_list(items: List[str], empty: str = "_(none observed yet)_") -> str:
    items = [i for i in items if i]
    if not items:
        return empty
    return "\n".join(f"- {i}" for i in items)


def generate_findings_md(
    target: str,
    graph: Optional[KnowledgeGraph] = None,
    generated_at: Optional[str] = None,
) -> str:
    graph = graph or KnowledgeGraph()

    requests = _by_type(graph, "captured-request")
    flags = _by_type(graph, "feature-flag")
    strings = _by_type(graph, "binary-string")
    traces = _by_type(graph, "dynamic-trace")
    hooks = _by_type(graph, "process-hook")
    risks = _by_type(graph, "risk")

    # API surfaces with their auth schemes
    api_lines = []
    for n in requests:
        data = json.loads(n.content)
        auth = ", ".join(data.get("auth_schemes", [])) or "none"
        api_lines.append(f"`{n.title}` — auth: {auth}")

    # Internal codenames = feature flags + flagged strings (capped, sorted)
    codenames = [n.title for n in flags] + [json.loads(n.content).get("value", n.title) for n in strings]
    codenames = sorted(set(codenames))[:100]

    tool_lines = []
    for n in traces + hooks:
        tool_lines.append(f"`{n.title}`")

    # Still-unextracted: sections with no evidence yet
    gaps = []
    if not requests:
        gaps.append("API surfaces — run a traffic capture (mitmproxy) and ingest the HAR.")
    if not traces and not hooks:
        gaps.append("Tool schema — attach Frida (objc_msgSend selector filter) to the running IDE.")
    if not flags:
        gaps.append("Feature flags / codenames — dump debug-command output and enumerate.")
    if not strings:
        gaps.append("Binary internals — run the static (strings/Ghidra) stage.")
    if not gaps:
        gaps.append("Memory-state model — capture and diff agent memory across turns.")

    header = f"# FINDINGS — {target}\n"
    if generated_at:
        header += f"\n_Generated: {generated_at}_\n"

    parts = [
        header,
        "## Executive Summary\n\n"
        f"- API surfaces observed: **{len(requests)}**\n"
        f"- Feature flags / codenames: **{len(flags)}**\n"
        f"- Binary strings of interest: **{len(strings)}**\n"
        f"- Dynamic traces / hooks: **{len(traces) + len(hooks)}**\n"
        f"- Risk surfaces: **{len(risks)}**\n",
        "## API Surfaces\n\n" + _bullet_list(api_lines) + "\n",
        "## Completion / Payload Structure\n\n"
        + (_bullet_list([f"`{n.title}`" for n in requests]) if requests else "_(capture payloads to populate)_")
        + "\n",
        "## Internal Codenames\n\n" + _bullet_list(codenames) + "\n",
        "## Tool Schema\n\n" + _bullet_list(tool_lines) + "\n",
        "## Memory & State\n\n"
        + (_bullet_list([f"`{n.title}`" for n in risks]) if risks else "_(no memory-state model extracted yet)_")
        + "\n",
        "## Still Unextracted\n\n" + _bullet_list([f"[ ] {g}" for g in gaps]) + "\n",
        "---\n_Auto-generated by pi_ide_re.methodology from the content-addressed campaign graph._\n",
    ]
    return "\n".join(parts)


def generate_method_md(
    target: str,
    tools: Optional[List[str]] = None,
    steps: Optional[List[str]] = None,
    lessons: Optional[List[str]] = None,
    generated_at: Optional[str] = None,
) -> str:
    tools = tools or ["frida", "mitmproxy", "ghidra/strings", "httpx"]
    steps = steps or [
        "Acquire the target binary/app bundle and record its hash + version.",
        "Run the static stage (strings/Ghidra) and review key_strings.",
        "Attach Frida with the objc_msgSend selector filter; collect dynamic traces.",
        "Start the mitmproxy capture, exercise the IDE, export a HAR; ingest it.",
        "Enumerate feature flags from debug-command output.",
        "Generate FINDINGS.md from the campaign graph and triage the gaps.",
    ]

    header = f"# METHOD — {target}\n"
    if generated_at:
        header += f"\n_Generated: {generated_at}_\n"

    phase_lines = "\n".join(f"{i + 1}. **{name}** — {desc}" for i, (name, desc) in enumerate(FIVE_PHASES))
    step_lines = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps))

    parts = [
        header,
        "## Tools Used\n\n" + _bullet_list(sorted(tools)) + "\n",
        "## Five-Phase Playbook\n\n" + phase_lines + "\n",
        "## Reproduction Steps\n\n" + step_lines + "\n",
        "## Key Lessons\n\n"
        + _bullet_list(lessons or [], empty="_(record lessons as the campaign progresses)_")
        + "\n",
        "---\n_Auto-generated by pi_ide_re.methodology._\n",
    ]
    return "\n".join(parts)


def write_methodology(
    target: str,
    graph: Optional[KnowledgeGraph] = None,
    root: Union[str, Path] = "re",
    *,
    tools: Optional[List[str]] = None,
    steps: Optional[List[str]] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Path]:
    """Write FINDINGS.md + METHOD.md into ``<root>/<target>/`` and return paths."""
    out_dir = Path(root).expanduser().resolve() / target
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "FINDINGS.md"
    method_path = out_dir / "METHOD.md"
    findings_path.write_text(generate_findings_md(target, graph=graph, generated_at=generated_at), encoding="utf-8")
    method_path.write_text(
        generate_method_md(target, tools=tools, steps=steps, generated_at=generated_at), encoding="utf-8"
    )
    return {"findings": findings_path, "method": method_path}
