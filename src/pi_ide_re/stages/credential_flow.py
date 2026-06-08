"""
credential_flow.py - auth/credential-flow capture stage (Theme 1, P2).

RE / authorized-testing use only. Adapts the credential-dumper and
ssl-pinning-bypass Frida scripts to map where an AI IDE keeps its OAuth /
session / API-key material.

SAFETY INVARIANT (enforced by tests): raw secret VALUES never enter the graph.
Each observation is stored as a content-addressed ``dynamic-trace`` node holding
the source + key NAME + a one-way fingerprint of the value, so the same secret
can be correlated across sources without ever persisting it. A single ``risk``
node summarizes the exposure surface for downstream dual-use / hardening work
(maps to pi_extension_governor).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..graph_schema import DynamicTrace, EdgeMetadata, GraphEdge, GraphNode, NodeMetadata, content_hash
from .base import StageResult

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "frida_templates"

_SCRIPTS = {
    "credential-dumper": "credential-dumper.js",
    "ssl-pinning-bypass": "ssl-pinning-bypass.js",
}


def redact_secret(value: Optional[str]) -> str:
    """One-way fingerprint of a secret. Never reversible, stable per value."""
    if not value:
        return "<empty>"
    return f"<redacted:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]}>"


class CredentialFlowStage:
    name = "credential-flow"

    # ---- bundled scripts -----------------------------------------------

    def bundled_scripts(self) -> List[str]:
        return sorted(_SCRIPTS)

    def load_script(self, name: str) -> str:
        if name not in _SCRIPTS:
            raise KeyError(f"unknown credential script '{name}'. Known: {self.bundled_scripts()}")
        return (_TEMPLATE_DIR / _SCRIPTS[name]).read_text(encoding="utf-8")

    # ---- deterministic ingest ------------------------------------------

    def ingest(self, capture: Dict[str, Any]) -> StageResult:
        target = capture.get("target", "unknown-target")
        creds = capture.get("credentials", [])
        ssl_bypassed = bool(capture.get("ssl_pinning_bypassed", False))

        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}

        risk_id = f"risk/{content_hash({'target': target, 'risk': 'credential-exposure'})}"

        for c in creds:
            source = c.get("source", "unknown")
            key = c.get("key", "")
            ctype = c.get("type", "unknown")
            fingerprint = redact_secret(c.get("value"))
            by_type[ctype] = by_type.get(ctype, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1

            trace = DynamicTrace(
                target=target,
                hook=f"credential:{source}",
                findings=[f"{key} -> {fingerprint} ({ctype})"],
            )
            node = trace.to_graph_node(source_page="(credential-flow)")
            nodes.append(node)
            edges.append(
                GraphEdge(
                    source=node.id,
                    target=risk_id,
                    metadata=EdgeMetadata(relation_type="data-flow", created_by=self.name),
                )
            )

        risk = GraphNode(
            id=risk_id,
            type="risk",
            title=f"Credential exposure surface: {target}",
            content=(
                f"{len(creds)} credential artifact(s) observed across "
                f"{len(by_source)} source(s); SSL pinning "
                f"{'bypassed' if ssl_bypassed else 'intact'}. Values are fingerprinted, never stored. "
                "Dual-use note: maps to pi_extension_governor secret-handling controls."
            ),
            metadata=NodeMetadata(source_page="(credential-flow)", tags=["risk", "credential", "auth"]),
        )
        nodes.append(risk)

        return StageResult(
            stage=self.name,
            nodes=nodes,
            edges=edges,
            summary={
                "target": target,
                "credentials": len(creds),
                "ssl_pinning_bypassed": ssl_bypassed,
                "by_type": by_type,
                "by_source": by_source,
            },
        )

    def ingest_file(self, path: Any) -> StageResult:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest(json.load(f))
