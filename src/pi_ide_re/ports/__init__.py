"""
pi_ide_re.ports - the "port" pipeline (Theme 3, P2).

Turns an RE finding (a graph node) into a reusable DEFENSIVE component, exactly
like hermes-re/ports/*: a ``SKILL.md`` (frontmatter + Core Ideas Ported / When
to Use / Procedure / Integration / Attack Surface) plus a minimal runnable
adapter, registered in a content-stable ``ports/index.json``.

The flow is finding -> port: an offensive observation becomes a hardening unit
wired into the pi-platform's defensive components. SKILL.md is deterministic;
the adapter is always valid Python.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Union

from ..graph_schema import GraphNode

# node.type -> (category, description, dual_use, integration, procedure)
_CATEGORY_BY_TYPE: Dict[str, Tuple[str, str, List[str], List[str], List[str]]] = {
    "captured-request": (
        "protocol",
        "A hardened, audited API-surface client/guard ported from an observed endpoint.",
        ["api-replay", "traffic-audit"],
        ["pi_micro_agents (cors/http-method/mime auditors)", "pi_console auth_guard"],
        [
            "Enumerate the endpoint + required auth scheme from the capture.",
            "Wrap calls behind the audited client; reject missing/extra auth headers.",
            "Emit each call to the event journal for replay.",
        ],
    ),
    "dynamic-trace": (
        "instrumentation",
        "A controlled tool/agent invocation surface ported from observed runtime hooks.",
        ["agent-of-agents", "tool-broker"],
        ["pi_extension_governor (sandbox + inspector)", "pi_micro_agents orchestrator"],
        [
            "Identify the hooked selector/IPC surface.",
            "Route equivalent calls through the governed tool broker.",
            "Block introspection escapes via the AST inspector.",
        ],
    ),
    "risk": (
        "secret-handling",
        "A secret-handling guard ported from an observed credential-exposure surface.",
        ["fingerprint-only-logging", "secret-scanner"],
        ["pi_extension_governor (secret controls)"],
        [
            "Locate where the IDE stores/reads credentials.",
            "Replace raw logging with one-way fingerprints (never store values).",
            "Scan for the exposure pattern on install.",
        ],
    ),
    "binary-string": (
        "sandbox",
        "A fail-closed sandbox policy ported from observed sandbox/exec strings.",
        ["sandbox-policy", "egress-isolation"],
        ["pi_extension_governor (fail-closed subprocess sandbox)"],
        [
            "Map the discovered policy/exec strings to capabilities.",
            "Express them as a fail-closed policy (deny by default).",
            "Enforce via the subprocess sandbox + rlimits.",
        ],
    ),
    "feature-flag": (
        "flag-gating",
        "A governed feature-flag gate ported from observed flags/codenames.",
        ["flag-gating", "scope-guard"],
        ["pi_agent_chain governance (objective_tracker scope guards)"],
        [
            "Catalogue the flags + their lifecycle status.",
            "Gate ungated behavior behind the governance scope guard.",
            "Audit flips through the ledger.",
        ],
    ),
}

_GENERIC: Tuple[str, str, List[str], List[str], List[str]] = (
    "generic",
    "A reusable component ported from an RE insight.",
    ["dual-use"],
    ["pi_micro_agents"],
    ["Document the finding.", "Define the defensive invariant.", "Wire it into the platform."],
)


def _kebab(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _camel(slug: str) -> str:
    return "".join(part.capitalize() for part in slug.split("-")) + "Adapter"


@dataclass
class Port:
    name: str  # kebab id ending in "-port"
    title: str
    source: str
    description: str
    dual_use: List[str] = field(default_factory=list)
    integration: List[str] = field(default_factory=list)
    procedure: List[str] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    target: str = ""

    def slug(self) -> str:
        return self.name


def port_from_node(node: GraphNode, target: str = "target") -> Port:
    category, desc, dual_use, integration, procedure = _CATEGORY_BY_TYPE.get(node.type, _GENERIC)
    name = f"{_kebab(target)}-{category}-port"
    return Port(
        name=name,
        title=f"{target} {category.replace('-', ' ').title()} Port",
        source=f"{node.type}:{node.title}",
        description=desc,
        dual_use=list(dual_use),
        integration=list(integration),
        procedure=list(procedure),
        attack_surface=[node.title],
        target=target,
    )


def render_skill_md(port: Port) -> str:
    fm = [
        "---",
        f"name: {port.slug()}",
        f'description: "{port.description}"',
        "platforms: [macos, linux]",
        "metadata:",
        f'  source_finding: "{port.source}"',
        f"  dual_use: [{', '.join(port.dual_use)}]",
        "  pi_integration:",
    ]
    fm += [f"    - {c}" for c in port.integration]
    fm.append("---")

    body = [
        "",
        f"# {port.title}",
        "",
        "## Core Ideas Ported",
        "",
        f"- Origin finding: `{port.source}`",
        f"- {port.description}",
        "",
        "## When to Use",
        "",
        f"- When defending the {port.target} surface this finding exposes.",
        "- When you need a reusable, governed equivalent of the offensive primitive.",
        "",
        "## Procedure",
        "",
    ]
    body += [f"{i + 1}. {step}" for i, step in enumerate(port.procedure)]
    body += ["", "## Integration", ""]
    body += [f"- {c}" for c in port.integration]
    body += ["", "## Attack Surface", ""]
    body += [f"- `{s}`" for s in port.attack_surface]
    body += ["", "---", f"_Auto-generated port (pi_ide_re.ports) from {port.source}._", ""]
    return "\n".join(fm + body)


def render_adapter(port: Port) -> str:
    cls = _camel(port.slug())
    return (
        f'"""{port.slug()} adapter.\n\n'
        f"Generated from RE finding: {port.source}.\n"
        'Minimal, runnable, governed equivalent of the ported primitive.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from typing import Any, Dict, Optional\n\n\n"
        f"class {cls}:\n"
        f"    slug = {port.slug()!r}\n"
        f"    source = {port.source!r}\n"
        f"    integration = {port.integration!r}\n\n"
        "    def run(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:\n"
        '        """Apply the ported defensive control. Stub: wire into integration targets."""\n'
        '        return {"port": self.slug, "source": self.source, "ok": True, "payload": payload or {}}\n\n\n'
        'if __name__ == "__main__":\n'
        "    import json\n"
        f"    print(json.dumps({cls}().run(), indent=2, sort_keys=True))\n"
    )


class PortRegistry:
    """Thread-safe registry of generated ports, persisted to ports/index.json."""

    _lock = threading.Lock()

    def __init__(self, root: Union[str, Path] = "re"):
        self.ports_dir = Path(root).expanduser().resolve() / "ports"
        self.index_path = self.ports_dir / "index.json"

    def _load(self) -> Dict:
        if self.index_path.exists():
            try:
                return json.loads(self.index_path.read_text())
            except Exception:
                pass
        return {"version": 1, "ports": {}}

    def list_ports(self) -> List[str]:
        return sorted(self._load().get("ports", {}))

    def register(self, port: Port, skill_rel: str, adapter_rel: str) -> None:
        with self._lock:
            index = self._load()
            index["ports"][port.slug()] = {
                "title": port.title,
                "source": port.source,
                "skill": skill_rel,
                "adapter": adapter_rel,
                "integration": port.integration,
            }
            index["ports"] = {k: index["ports"][k] for k in sorted(index["ports"])}
            self.ports_dir.mkdir(parents=True, exist_ok=True)
            self.index_path.write_text(json.dumps(index, indent=2, sort_keys=True))


def generate_port(port: Port, root: Union[str, Path] = "re") -> Dict[str, Path]:
    registry = PortRegistry(root=root)
    port_dir = registry.ports_dir / port.slug()
    port_dir.mkdir(parents=True, exist_ok=True)
    skill_path = port_dir / "SKILL.md"
    adapter_path = port_dir / f"{port.slug().replace('-', '_')}_adapter.py"
    skill_path.write_text(render_skill_md(port), encoding="utf-8")
    adapter_path.write_text(render_adapter(port), encoding="utf-8")
    registry.register(
        port,
        skill_rel=str(skill_path.relative_to(registry.ports_dir)),
        adapter_rel=str(adapter_path.relative_to(registry.ports_dir)),
    )
    return {"skill": skill_path, "adapter": adapter_path, "dir": port_dir}
