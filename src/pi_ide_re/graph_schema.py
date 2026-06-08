"""
graph_schema.py - Typed Knowledge Graph models (v1.2)

Shared schema used by the ingest pipeline and all graph-management micro-agents.

v1.2 adds the *dynamic RE* node types (Frida traces, captured traffic, binary
strings, functions of interest, process hooks, feature flags) plus a
content-addressed hashing helper.

Determinism contract
--------------------
The graph is content-addressed: a node's id is a hash of its STABLE identity,
not of the run that produced it. Volatile capture metadata - pids, wall-clock
timestamps, listening ports, runtime load addresses, secret values - is
retained on the node for humans but EXCLUDED from the hash. Re-ingesting the
same captured artifact therefore yields the same node id every time. This
mirrors the platform's compute_hash discipline (see pi_event_fabric/bus/core.py
`_canonical` and the mesh ExecutionReceipt hash, which both drop wall-clock /
resource fields before hashing).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

NodeType = Literal[
    "deep-research",
    "entity",
    "insight",
    "code-artifact",
    "risk",
    # v1.2 dynamic-RE node types
    "dynamic-trace",
    "captured-request",
    "binary-string",
    "function-interest",
    "process-hook",
    "feature-flag",
]

RelationType = Literal[
    "needs-research",
    "references",
    "blocks",
    "extends",
    "contains",
    "protocol",
    "data-flow",
    # v1.2 dynamic-RE relations
    "hooks",
    "captures",
    "observed-in",
]


# ============================================================
# CONTENT-ADDRESSED HASHING
# ============================================================


def _canonical(value: Any) -> Any:
    """Recursively canonicalize a value for stable hashing.

    Sets -> sorted lists, dict keys sorted at serialization time. Mirrors the
    `_canonical` helper added to the event fabric so set/dict ordering never
    leaks into a hash.
    """
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (set, frozenset)):
        return sorted(_canonical(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def content_hash(payload: Dict[str, Any], *, exclude: Optional[set] = None, length: int = 16) -> str:
    """Deterministic short content hash of `payload`.

    `exclude` names volatile keys to drop before hashing (timestamps, pids,
    ports, load addresses). Key order and set order never affect the result.
    """
    exclude = exclude or set()
    filtered = {k: v for k, v in payload.items() if k not in exclude}
    canonical = json.dumps(_canonical(filtered), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:length]


# ============================================================
# CORE TYPED GRAPH MODELS
# ============================================================


class NodeMetadata(BaseModel):
    source_page: str
    # Wall-clock is volatile: leaving it None by default keeps a serialized graph
    # byte-reproducible across runs (content-addressing extends to the whole
    # artifact, not just node ids). Callers may set it explicitly when they want
    # a human timestamp. Mirrors the audit's "no wall-clock in the hash" rule.
    last_updated: Optional[datetime] = None
    priority_score: float = 0.0
    tags: List[str] = Field(default_factory=list)
    pi_agents_applied: List[str] = Field(default_factory=list)


class EdgeMetadata(BaseModel):
    relation_type: RelationType
    confidence: float = 1.0
    created_by: str = "ingest-pipeline"


class GraphNode(BaseModel):
    id: str
    type: NodeType
    title: str
    content: str
    metadata: NodeMetadata = Field(default_factory=lambda: NodeMetadata(source_page="(synthetic)"))


class GraphEdge(BaseModel):
    source: str
    target: str
    metadata: EdgeMetadata = Field(default_factory=lambda: EdgeMetadata(relation_type="references"))


class KnowledgeGraph(BaseModel):
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)
    version: str = "1.2"


# ============================================================
# DYNAMIC-RE ARTIFACT MODELS
# ============================================================
#
# Each artifact knows (a) its STABLE identity (what makes it the same
# observation across runs) and (b) the volatile capture metadata it carries for
# humans. `node_id()` hashes only the identity; `to_graph_node()` produces a
# content-addressed GraphNode whose content keeps the volatile detail.


class _Artifact(BaseModel):
    """Base for content-addressed RE artifacts."""

    NODE_TYPE: str = ""  # overridden per subclass

    def _identity(self) -> Dict[str, Any]:  # pragma: no cover - overridden
        raise NotImplementedError

    def node_id(self) -> str:
        return f"{self.NODE_TYPE}/{content_hash(self._identity())}"

    def _node_title(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def to_graph_node(self, source_page: str = "(dynamic-capture)") -> GraphNode:
        return GraphNode(
            id=self.node_id(),
            type=self.NODE_TYPE,  # type: ignore[arg-type]
            title=self._node_title(),
            content=self.model_dump_json(indent=2),
            metadata=NodeMetadata(source_page=source_page, tags=[self.NODE_TYPE]),
        )


class DynamicTrace(_Artifact):
    """A Frida hook observation: which hook fired on which target, what it saw."""

    NODE_TYPE: str = "dynamic-trace"
    target: str  # stable: process name / app identifier
    hook: str  # stable: hook label, e.g. "objc_msgSend:tool" or "send"
    findings: List[str] = Field(default_factory=list)  # observed selectors/strings
    pid: Optional[int] = None  # volatile
    captured_at: Optional[str] = None  # volatile

    def _identity(self) -> Dict[str, Any]:
        return {"target": self.target, "hook": self.hook, "findings": sorted(set(self.findings))}

    def _node_title(self) -> str:
        return f"{self.target} :: {self.hook}"


class CapturedRequest(_Artifact):
    """An HTTP(S)/WS endpoint observed via traffic capture.

    Identity is the *endpoint shape* (method + host + path + content-type), so
    repeated calls to the same endpoint collapse to one node - the API-surface
    view. Auth is recorded as the set of header NAMES present, never the values.
    """

    NODE_TYPE: str = "captured-request"
    method: str
    url: str  # full url retained for humans; volatile query params ignored in identity
    host: str
    path: str
    auth_schemes: List[str] = Field(default_factory=list)  # header names only, never values
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    is_websocket: bool = False
    timestamp: Optional[str] = None  # volatile

    def _identity(self) -> Dict[str, Any]:
        return {
            "method": self.method.upper(),
            "host": self.host,
            "path": self.path,
            "content_type": self.content_type,
            "is_websocket": self.is_websocket,
            "auth_schemes": sorted({s.lower() for s in self.auth_schemes}),
        }

    def _node_title(self) -> str:
        return f"{self.method.upper()} {self.host}{self.path}"


class BinaryString(_Artifact):
    """An interesting string found in a binary (Ghidra/strings). Address volatile."""

    NODE_TYPE: str = "binary-string"
    value: str
    context: str = ""  # the keyword/category that flagged it
    addr: Optional[str] = None  # volatile (build-dependent)

    def _identity(self) -> Dict[str, Any]:
        return {"value": self.value, "context": self.context}

    def _node_title(self) -> str:
        return (self.value[:60] + "...") if len(self.value) > 60 else self.value


class FunctionInterest(_Artifact):
    """A function of interest found in a binary. Entry address volatile."""

    NODE_TYPE: str = "function-interest"
    name: str
    keywords: List[str] = Field(default_factory=list)
    entry: Optional[str] = None  # volatile

    def _identity(self) -> Dict[str, Any]:
        return {"name": self.name, "keywords": sorted(set(self.keywords))}

    def _node_title(self) -> str:
        return self.name


class ProcessHook(_Artifact):
    """A configured instrumentation hook (template + selector) and what it saw.

    Identity is the (template, selector) pair - the hook configuration - so the
    same hook across runs is one node; `findings` are per-run observations.
    """

    NODE_TYPE: str = "process-hook"
    template: str
    selector: str
    findings: List[str] = Field(default_factory=list)  # volatile observations

    def _identity(self) -> Dict[str, Any]:
        return {"template": self.template, "selector": self.selector}

    def _node_title(self) -> str:
        return f"{self.template} :: {self.selector}"


class FeatureFlag(_Artifact):
    """An enumerated feature flag / internal codename."""

    NODE_TYPE: str = "feature-flag"
    name: str
    status: str = "unknown"  # stable | experimental | dev | deprecated | unknown
    value: Optional[str] = None
    source: str = ""

    def _identity(self) -> Dict[str, Any]:
        return {"name": self.name}

    def _node_title(self) -> str:
        return self.name


# ============================================================
# TYPED GRAPH PERSISTENCE
# ============================================================
#
# Canonical home for graph persistence (ingest.py keeps a legacy copy for back
# compat). New code - including the dynamic stages - should use these.


def _graph_path(vault_path: str | Path) -> Path:
    return Path(vault_path) / "knowledge_graph.json"


def load_knowledge_graph(vault_path: str | Path) -> KnowledgeGraph:
    """Load or initialize the typed KnowledgeGraph from disk."""
    graph_file = _graph_path(vault_path)
    if graph_file.exists():
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                return KnowledgeGraph.model_validate(json.load(f))
        except Exception:
            pass
    return KnowledgeGraph()


def save_knowledge_graph(graph: KnowledgeGraph, vault_path: str | Path) -> None:
    """Persist the typed graph deterministically (sorted keys)."""
    graph_file = _graph_path(vault_path)
    graph_file.parent.mkdir(parents=True, exist_ok=True)
    with open(graph_file, "w", encoding="utf-8") as f:
        json.dump(graph.model_dump(mode="json"), f, indent=2, sort_keys=True, default=str)


def add_to_typed_graph(
    graph: KnowledgeGraph,
    node: Optional[GraphNode] = None,
    edge: Optional[GraphEdge] = None,
    vault_path: str | Path = "vault",
) -> None:
    """Add node and/or edge to the typed graph and persist."""
    if node:
        graph.nodes[node.id] = node
    if edge:
        graph.edges.append(edge)
    save_knowledge_graph(graph, vault_path)
