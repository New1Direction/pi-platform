"""pi-semantic-radius: Immutable topology and risk models.

No inference. No LLM calls. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Topology Primitives
# ──────────────────────────────

class TopologyNode(BaseModel):
    node_id: str
    node_type: str = "UNKNOWN"  # endpoint, service, database, queue
    dependencies: List[str] = Field(default_factory=list)
    auth_fields: List[str] = Field(default_factory=list)
    mutation_class: str = "UNKNOWN"
    replay_class: str = "UNKNOWN"
    layer_id: str = ""
    model_config = {"frozen": True}


class TopologyEdge(BaseModel):
    edge_id: str
    upstream: str
    downstream: str
    edge_type: str = "UNKNOWN"  # direct_call, async_event, shared_state
    carries_auth: bool = False
    carries_state: bool = False
    model_config = {"frozen": True}


class TopologyGraph(BaseModel):
    graph_id: str
    nodes: Dict[str, TopologyNode] = Field(default_factory=dict)
    edges: List[TopologyEdge] = Field(default_factory=list)
    model_config = {"frozen": True}

    def fanout(self, node_id: str) -> int:
        return sum(1 for e in self.edges if e.upstream == node_id)

    def depth_from(self, node_id: str, visited: Optional[Set[str]] = None, _depth: int = 0) -> int:
        if _depth > 32:
            return 0  # bounded
        visited = visited or set()
        if node_id in visited:
            return 0
        visited.add(node_id)
        children = [e.downstream for e in self.edges if e.upstream == node_id]
        if not children:
            return 0
        return 1 + max(
            (self.depth_from(child, visited.copy(), _depth + 1) for child in children),
            default=0,
        )

    def reachable(self, node_id: str) -> Set[str]:
        visited: Set[str] = set()
        frontier = [node_id]
        while frontier:
            current = frontier.pop()
            if current in visited:
                continue
            visited.add(current)
            for e in self.edges:
                if e.upstream == current and e.downstream not in visited:
                    frontier.append(e.downstream)
        visited.discard(node_id)
        return visited


# ──────────────────────────────
#  Risk Score Models
# ──────────────────────────────

class RiskScore(BaseModel):
    score_id: str
    target_node: str
    # Propagation metrics
    dependency_expansion: int = 0
    topology_complexity_delta: float = 0.0
    fanout_delta: int = 0
    depth_delta: int = 0
    # Auth boundary
    auth_surface_expansion: int = 0
    auth_boundary_widening: bool = False
    # Replay hazard
    replay_hazard_spread: int = 0
    replay_propagation_depth: int = 0
    # Mutation impact
    downstream_mutation_impact: int = 0
    side_effect_bound_expansion: int = 0
    # Deterministic hash
    input_hash: str = ""
    model_config = {"frozen": True}


class RiskReport(BaseModel):
    report_id: str
    baseline_graph_id: str = ""
    modified_graph_id: str = ""
    scores: List[RiskScore] = Field(default_factory=list)
    # Aggregates
    total_dependency_expansion: int = 0
    total_auth_surface_expansion: int = 0
    total_replay_hazard_spread: int = 0
    total_downstream_mutation_impact: int = 0
    max_topology_depth_delta: int = 0
    max_fanout_delta: int = 0
    # Policy limit violations
    limits_exceeded: List[str] = Field(default_factory=list)
    # Deterministic hash
    report_hash: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = json.dumps(
            self.model_dump(exclude={"report_hash", "generated_at"}),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()


# ──────────────────────────────
#  Pass Results
# ──────────────────────────────

class PassResult(BaseModel):
    pass_name: str
    status: Literal["PASS", "FAIL", "BOUNDED"] = "PASS"
    violations: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    model_config = {"frozen": True}
