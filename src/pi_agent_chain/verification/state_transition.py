"""State Transition Validator — Phase 4 of verification subsystem.

Replay-Constrained Protocol Finite State Machine Extraction.

Key constraints:
- FSM is bounded (max_nodes, max_edges, max_fanout, max_depth)
- OBSERVED edges from temporal trace ordering
- VERIFIED edges ONLY via replay confirmation
- NO inferred edge without replay evidence
- Observational only. Returns governance violations. Never mutates state.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from pi_agent_chain.models import (
    AuthConsistencyReport,
    AuthInvariant,
    EpistemicState,
    GovernanceViolation,
    NormalizedTrafficPacket,
    ProtocolStateMachine,
    SemanticIRTrace,
    StateNode,
    TransitionConstraint,
    TransitionEdge,
    ValidationBoundsConfig,
)


class StateTransitionValidator:
    """Extract and validate a bounded protocol FSM from traces.

    NOT a generic graph builder. A replay-constrained FSM extractor.
    """

    REPLAY_CONFIDENCE_THRESHOLD = 0.85

    def __init__(self, bounds: Optional[ValidationBoundsConfig] = None) -> None:
        self.bounds = bounds or ValidationBoundsConfig()

    # ──────────────────────────────
    #  Public API
    # ──────────────────────────────

    def extract_fsm(
        self,
        traces: List[SemanticIRTrace],
        packets: List[NormalizedTrafficPacket],
        auth_report: AuthConsistencyReport,
        execution_id: str = "",
    ) -> Tuple[ProtocolStateMachine, List[GovernanceViolation]]:
        """Extract a bounded FSM from observed traces.

        Returns:
            ProtocolStateMachine — bounded, replay-constrained
            List[GovernanceViolation] — graph bounds and epistemic violations
        """
        violations: List[GovernanceViolation] = []

        # Build OBSERVED nodes from unique endpoints
        nodes = self._build_nodes(traces, execution_id)
        if len(nodes) > self.bounds.max_fsm_nodes:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"node_overflow:{execution_id}"),
                    rule="FSM_NODE_OVERFLOW",
                    worker_id="state_transition_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"observed_nodes": len(nodes), "max_nodes": self.bounds.max_fsm_nodes},
                    action_taken="HALT",
                )
            )
            nodes = nodes[: self.bounds.max_fsm_nodes]

        # Build OBSERVED edges from temporal trace ordering
        edges = self._build_edges(nodes, traces, packets, auth_report, execution_id)
        if len(edges) > self.bounds.max_fsm_edges:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"edge_overflow:{execution_id}"),
                    rule="FSM_EDGE_OVERFLOW",
                    worker_id="state_transition_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"observed_edges": len(edges), "max_edges": self.bounds.max_fsm_edges},
                    action_taken="HALT",
                )
            )
            edges = edges[: self.bounds.max_fsm_edges]

        # Check fanout bounds
        for node in nodes:
            fanout = sum(1 for e in edges if e.from_node == node.node_id)
            if fanout > self.bounds.max_fsm_fanout:
                violations.append(
                    GovernanceViolation(
                        violation_id=self._hash(f"fanout_overflow:{execution_id}:{node.node_id}"),
                        rule="FSM_FANOUT_OVERFLOW",
                        worker_id="state_transition_validator",
                        root_goal_id=execution_id,
                        severity="ERROR",
                        context={"node_id": node.node_id, "fanout": fanout, "max_fanout": self.bounds.max_fsm_fanout},
                        action_taken="TRUNCATE",
                    )
                )
                # Truncate outgoing edges for this node
                outgoing = [e for e in edges if e.from_node == node.node_id]
                for e_out in outgoing[self.bounds.max_fsm_fanout :]:
                    e_out.epistemic_state = EpistemicState.CONTESTED

        # Depth check via BFS
        max_depth_reached = self._compute_depth(nodes, edges)
        if max_depth_reached > self.bounds.max_fsm_depth:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"depth_overflow:{execution_id}"),
                    rule="FSM_DEPTH_OVERFLOW",
                    worker_id="state_transition_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"observed_depth": max_depth_reached, "max_depth": self.bounds.max_fsm_depth},
                    action_taken="HALT",
                )
            )

        # Apply replay confirmation gating
        edges, replay_violations = self._apply_replay_gate(edges, execution_id)
        violations.extend(replay_violations)

        # Apply auth dependency linkage
        edges = self._link_auth_dependencies(edges, nodes, auth_report)

        fsm = ProtocolStateMachine(
            fsm_id=self._hash(f"fsm:{execution_id}"),
            nodes=nodes,
            edges=edges,
            max_nodes=self.bounds.max_fsm_nodes,
            max_edges=self.bounds.max_fsm_edges,
            max_fanout=self.bounds.max_fsm_fanout,
            max_depth=self.bounds.max_fsm_depth,
            epistemic_state=EpistemicState.INFERRED if not violations else EpistemicState.CONTESTED,
        )

        return fsm, violations

    # ──────────────────────────────
    #  Node Construction
    # ──────────────────────────────

    @staticmethod
    def _build_nodes(
        traces: List[SemanticIRTrace],
        execution_id: str,
    ) -> List[StateNode]:
        """Create one StateNode per unique endpoint+method."""
        seen: Set[str] = set()
        nodes: List[StateNode] = []
        for t in traces:
            key = f"{t.method}:{t.endpoint_template}"
            if key in seen:
                continue
            seen.add(key)
            nodes.append(
                StateNode(
                    node_id=hashlib.sha256(key.encode()).hexdigest()[:16],
                    endpoint_template=t.endpoint_template,
                    method=t.method,
                )
            )
        return nodes

    # ──────────────────────────────
    #  Edge Construction
    # ──────────────────────────────

    def _build_edges(
        self,
        nodes: List[StateNode],
        traces: List[SemanticIRTrace],
        packets: List[NormalizedTrafficPacket],
        auth_report: AuthConsistencyReport,
        execution_id: str,
    ) -> List[TransitionEdge]:
        """Build OBSERVED edges from temporal trace ordering.

        Temporal adjacency != protocol causality. All edges start OBSERVED.
        Replay confirmation required for VERIFIED promotion.
        """
        node_map: Dict[str, StateNode] = {n.node_id: n for n in nodes}

        # Order traces by packet timestamps
        endpoint_to_packet: Dict[Tuple[str, str], int] = {}
        for p in packets:
            endpoint_to_packet[(p.endpoint_path_template, p.method)] = p.timestamp

        sorted_traces = sorted(
            traces,
            key=lambda t: endpoint_to_packet.get((t.endpoint_template, t.method), 0),
        )

        edges: List[TransitionEdge] = []
        for i in range(len(sorted_traces) - 1):
            curr = sorted_traces[i]
            nxt = sorted_traces[i + 1]
            from_id = hashlib.sha256(f"{curr.method}:{curr.endpoint_template}".encode()).hexdigest()[:16]
            to_id = hashlib.sha256(f"{nxt.method}:{nxt.endpoint_template}".encode()).hexdigest()[:16]

            if from_id not in node_map or to_id not in node_map:
                continue
            if from_id == to_id:
                continue  # No self-loops

            edge_id = self._hash(f"edge:{from_id}->{to_id}:{execution_id}")

            # Build default OBSERVED edge with REPLAY_REQUIRED constraint
            constraints = [
                TransitionConstraint(
                    constraint_type="REPLAY_REQUIRED",
                    description="Temporal edge requires replay confirmation: to_node must fail or change semantic class when from_node is absent.",
                )
            ]

            edges.append(
                TransitionEdge(
                    edge_id=edge_id,
                    from_node=from_id,
                    to_node=to_id,
                    observed_count=1,
                    replay_confirmed_count=0,
                    constraints=constraints,
                    replay_confidence=0.0,
                    epistemic_state=EpistemicState.OBSERVED,
                )
            )

        # Merge duplicate edges (same from->to)
        merged: Dict[str, TransitionEdge] = {}
        for e in edges:
            if e.edge_id not in merged:
                merged[e.edge_id] = e
            else:
                merged[e.edge_id].observed_count += 1

        return list(merged.values())

    # ──────────────────────────────
    #  Replay Gate
    # ──────────────────────────────

    def _apply_replay_gate(
        self,
        edges: List[TransitionEdge],
        execution_id: str,
    ) -> Tuple[List[TransitionEdge], List[GovernanceViolation]]:
        """Gate edges through replay confirmation.

        Edges with replay_confirmed_count > 0 get promoted to INFERRED.
        Edges with confidence >= threshold get promoted to INFERRED.
        All others remain OBSERVED.
        """
        violations: List[GovernanceViolation] = []
        for edge in edges:
            if edge.replay_confirmed_count > 0:
                edge.epistemic_state = EpistemicState.INFERRED
                edge.replay_confidence = min(
                    edge.replay_confidence + 0.3 * edge.replay_confirmed_count,
                    1.0,
                )
            elif edge.observed_count >= 5:
                # High observational count with no replay is CONTESTED, not INFERRED
                edge.epistemic_state = EpistemicState.CONTESTED
                violations.append(
                    GovernanceViolation(
                        violation_id=self._hash(f"unverified_edge:{edge.edge_id}"),
                        rule="TRANSITION_UNVERIFIED_BY_REPLAY",
                        worker_id="state_transition_validator",
                        root_goal_id=execution_id,
                        severity="WARNING",
                        context={
                            "edge_id": edge.edge_id,
                            "from_node": edge.from_node,
                            "to_node": edge.to_node,
                            "observed_count": edge.observed_count,
                            "replay_confirmed_count": edge.replay_confirmed_count,
                        },
                        action_taken="CONTEST",
                    )
                )
        return edges, violations

    # ──────────────────────────────
    #  Auth Dependency Linkage
    # ──────────────────────────────

    @staticmethod
    def _link_auth_dependencies(
        edges: List[TransitionEdge],
        nodes: List[StateNode],
        auth_report: AuthConsistencyReport,
    ) -> List[TransitionEdge]:
        """Link TransitionEdges to relevant auth invariants.

        Adds AUTH_REQUIRED constraints to edges where auth transitions were observed.
        """
        node_map: Dict[str, StateNode] = {n.node_id: n for n in nodes}
        # Map invariants to endpoints
        auth_endpoints: Set[str] = set()
        for inv in auth_report.invariants:
            auth_endpoints.update(inv.affected_endpoints)

        for edge in edges:
            # Find if the to_node endpoint requires auth
            to_node_obj = node_map.get(edge.to_node)
            if to_node_obj and to_node_obj.endpoint_template in auth_endpoints:
                relevant = [inv.invariant_id for inv in auth_report.invariants
                            if to_node_obj.endpoint_template in inv.affected_endpoints]
                edge.auth_dependencies = relevant

        return edges

    # ──────────────────────────────
    #  Depth computation
    # ──────────────────────────────

    @staticmethod
    def _compute_depth(nodes: List[StateNode], edges: List[TransitionEdge]) -> int:
        """BFS to compute max depth from any source node."""
        if not nodes or not edges:
            return 0

        adjacency: Dict[str, List[str]] = defaultdict(list)
        for e in edges:
            adjacency[e.from_node].append(e.to_node)

        max_depth = 0
        for start in {n.node_id for n in nodes}:
            depth: Dict[str, int] = {start: 0}
            queue = [start]
            while queue:
                curr = queue.pop(0)
                for nxt in adjacency.get(curr, []):
                    if nxt not in depth:
                        depth[nxt] = depth[curr] + 1
                        queue.append(nxt)
                        max_depth = max(max_depth, depth[nxt])

        return max_depth

    @staticmethod
    def _hash(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:16]
