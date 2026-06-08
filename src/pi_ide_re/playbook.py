"""
playbook.py - the formalized 5-phase RE campaign (Theme 2, P2).

Wires the individual stages into one repeatable, typed flow:

    acquisition -> static -> dynamic-capture -> protocol-mapping -> feature-extraction

A ``Campaign`` runs each phase, merges that phase's content-addressed nodes into
a single KnowledgeGraph, records per-phase provenance, and can persist the graph
+ auto-generate FINDINGS.md / METHOD.md. Because every stage is deterministic
and content-addressed, the same inputs reproduce the same campaign graph - so a
campaign is replayable from its saved artifacts (the determinism guarantee the
whole platform is built on, carried into the RE tooling).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .artifacts import ArtifactStore
from .graph_schema import GraphNode, KnowledgeGraph, NodeMetadata, content_hash, save_knowledge_graph
from .methodology import write_methodology
from .stages.base import StageResult
from .stages.credential_flow import CredentialFlowStage
from .stages.dynamic_trace import DynamicTraceStage
from .stages.feature_flags import FeatureFlagStage
from .stages.ghidra_static import GhidraStaticStage
from .stages.traffic_capture import TrafficCaptureStage

PHASES = ["acquisition", "static", "dynamic-capture", "protocol-mapping", "feature-extraction"]


@dataclass
class PhaseRecord:
    phase: str
    stage: str
    node_count: int
    summary: Dict[str, Any] = field(default_factory=dict)


class Campaign:
    """A 5-phase RE campaign against one target."""

    def __init__(self, target: str, root: Union[str, Path] = "re"):
        self.target = target
        self.root = Path(root)
        self.store = ArtifactStore(root, target)
        self.graph = KnowledgeGraph()
        self.records: List[PhaseRecord] = []
        # Single auditable transition log (Theme 4 P3). Every graph mutation
        # flows through _dispatch and appends one entry here.
        self.transitions: List[Dict[str, Any]] = []

    # ---- internal: the single labeled dispatcher ------------------------

    def state_hash(self) -> str:
        """Canonical content hash of the current graph (its node-id set)."""
        return content_hash({"nodes": sorted(self.graph.nodes.keys())})

    def _dispatch(self, phase: str, result: StageResult) -> StageResult:
        """The ONE site through which all phase transitions mutate the graph."""
        before = len(self.graph.nodes)
        result.add_to(self.graph)
        after = len(self.graph.nodes)
        self.transitions.append(
            {
                "seq": len(self.transitions) + 1,
                "phase": phase,
                "stage": result.stage,
                "nodes_added": after - before,
                "state_hash": self.state_hash(),
            }
        )
        self.records.append(
            PhaseRecord(phase=phase, stage=result.stage, node_count=len(result.nodes), summary=result.summary)
        )
        return result

    # ---- phase 1: acquisition ------------------------------------------

    def acquire(
        self, *, binary_path: Optional[str] = None, sha256: Optional[str] = None, size: Optional[int] = None, version: str = ""
    ) -> PhaseRecord:
        identity = {"sha256": sha256} if sha256 else {"path": binary_path or self.target}
        node = GraphNode(
            id=f"code-artifact/{content_hash(identity)}",
            type="code-artifact",
            title=f"{self.target} binary",
            content=(
                f"target: {self.target}\nsha256: {sha256 or '?'}\nsize: {size or '?'}\n"
                f"version: {version or '?'}\npath: {binary_path or '?'}"
            ),
            metadata=NodeMetadata(source_page="(acquisition)", tags=["code-artifact", "acquisition"]),
        )
        result = StageResult(stage="acquisition", nodes=[node], edges=[], summary={"sha256": sha256})
        self._dispatch("acquisition", result)
        return self.records[-1]

    # ---- phase 2: static -----------------------------------------------

    def static(
        self, *, strings_text: Optional[str] = None, dump: Optional[Dict[str, Any]] = None, keywords: Optional[List[str]] = None
    ) -> StageResult:
        stage = GhidraStaticStage()
        if dump is not None:
            result = stage.ingest(dump, keywords=keywords)
        else:
            result = stage.scan_strings(strings_text or "", keywords=keywords)
        return self._dispatch("static", result)

    # ---- phase 3: dynamic capture --------------------------------------

    def dynamic(self, *, capture: Optional[Dict[str, Any]] = None) -> StageResult:
        result = DynamicTraceStage().ingest(capture or {"target": self.target, "messages": []})
        return self._dispatch("dynamic-capture", result)

    def credentials(self, *, capture: Dict[str, Any]) -> StageResult:
        """Optional credential-flow sub-stage of dynamic capture."""
        return self._dispatch("dynamic-capture", CredentialFlowStage().ingest(capture))

    # ---- phase 4: protocol mapping -------------------------------------

    def protocol(self, *, har: Optional[Dict[str, Any]] = None, native: Optional[Dict[str, Any]] = None) -> StageResult:
        stage = TrafficCaptureStage()
        if har is not None:
            result = stage.ingest_har(har)
        else:
            result = stage.ingest(native or {})
        return self._dispatch("protocol-mapping", result)

    # ---- phase 5: feature extraction -----------------------------------

    def features(self, *, text: Optional[str] = None, flags: Optional[List[Dict[str, Any]]] = None) -> StageResult:
        stage = FeatureFlagStage()
        if flags is not None:
            result = stage.ingest(flags)
        else:
            result = stage.extract(text or "")
        return self._dispatch("feature-extraction", result)

    # ---- assembly / output ---------------------------------------------

    def assemble(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for n in self.graph.nodes.values():
            by_type[n.type] = by_type.get(n.type, 0) + 1
        return {
            "target": self.target,
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
            "by_type": by_type,
            "phases": [r.phase for r in self.records],
            "records": [vars(r) for r in self.records],
        }

    def persist(self) -> Path:
        out = self.root.expanduser().resolve() / self.target
        save_knowledge_graph(self.graph, out)
        return out / "knowledge_graph.json"

    def write_docs(self, **kwargs) -> Dict[str, Path]:
        return write_methodology(self.target, self.graph, root=self.root, **kwargs)
