"""Blast Radius Validation Pass.

Deterministic enforcement of topology and scope expansion limits.

Rules enforced:
  1. Dependency expansion limits (edges per endpoint, cross-service edges)
  2. Topology complexity growth (fanout, graph depth, complexity score)
  3. Auth surface expansion (auth fields per endpoint, unconfirmed bindings)
  4. Replay propagation scope growth (replay scope nodes, side-effect bound count)

Consumes: DependencyGraph, SemanticIRTrace, AuthInvariant, ProtocolStateMachine.
No inference. Pure numeric deterministic bounds checking.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pi_semantic_validator.policy import ArchitecturePolicy
from pi_semantic_validator.models import (
    AuthInvariant,
    DependencyGraph,
    GovernanceViolation,
    ProtocolStateMachine,
    SemanticIRTrace,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.violations import ViolationBuilder


class BlastRadiusValidationPass:
    """Deterministic blast radius validator."""

    def execute(self, envelope: Dict[str, Any]) -> WorkerResponse:
        execution_id: str = envelope["execution_id"]
        artifacts: List[ValidationArtifact] = envelope["artifacts"]
        policy: ArchitecturePolicy = envelope["policy"]
        bounds: ValidationBoundsConfig = envelope["bounds"]

        builder = ViolationBuilder("blast_radius")
        violations: List[GovernanceViolation] = []
        evidence_count = 0

        dep_graphs: List[DependencyGraph] = []
        traces: List[SemanticIRTrace] = []
        invariants: List[AuthInvariant] = []
        fsms: List[ProtocolStateMachine] = []

        for art in artifacts:
            if art.artifact_type == "DependencyGraph" and isinstance(art.payload, dict):
                try:
                    dep_graphs.append(DependencyGraph.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_DEPENDENCY_GRAPH",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )
            elif art.artifact_type == "SemanticIRTrace" and isinstance(art.payload, dict):
                try:
                    traces.append(SemanticIRTrace.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_SEMANTIC_TRACE",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )
            elif art.artifact_type == "AuthInvariant" and isinstance(art.payload, dict):
                try:
                    invariants.append(AuthInvariant.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_AUTH_INVARIANT",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )
            elif art.artifact_type == "ProtocolStateMachine" and isinstance(art.payload, dict):
                try:
                    fsms.append(ProtocolStateMachine.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_PROTOCOL_FSM",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )

        limits = policy.blast_radius_limits

        # 1. Dependency expansion limits per graph
        max_graph_iter = min(len(dep_graphs), bounds.max_edges_per_graph)
        for gidx, graph in enumerate(dep_graphs[:max_graph_iter]):
            edge_count = len(graph.edges)
            node_count = len(graph.nodes)
            evidence_count += 1

            # Total cross-service edges
            cross_service = 0
            for edge in graph.edges:
                up_zone = policy.get_zone_for_endpoint(edge.upstream_endpoint)
                down_zone = policy.get_zone_for_endpoint(edge.downstream_endpoint)
                if up_zone and down_zone and up_zone.zone_id != down_zone.zone_id:
                    cross_service += 1

            if cross_service > limits.max_cross_service_edges:
                violations.append(
                    builder.critical(
                        rule="CROSS_SERVICE_EDGE_LIMIT_EXCEEDED",
                        provenance=[f"graph:{graph.session_window_id}"],
                        extra={
                            "cross_service_edges": cross_service,
                            "max_allowed": limits.max_cross_service_edges,
                        },
                    )
                )

            # Per-endpoint dependency count
            dep_counts: Dict[str, int] = {}
            for edge in graph.edges:
                dep_counts[edge.downstream_endpoint] = dep_counts.get(edge.downstream_endpoint, 0) + 1
                dep_counts[edge.upstream_endpoint] = dep_counts.get(edge.upstream_endpoint, 0) + 1

            for endpoint, count in dep_counts.items():
                if count > limits.max_dependencies_per_endpoint:
                    violations.append(
                        builder.error(
                            rule="DEPENDENCY_EXPANSION_LIMIT_EXCEEDED",
                            endpoint=endpoint,
                            provenance=[f"graph:{graph.session_window_id}"],
                            extra={
                                "dependency_count": count,
                                "max_allowed": limits.max_dependencies_per_endpoint,
                            },
                        )
                    )

            # Fanout per endpoint
            fanout: Dict[str, int] = {}
            for edge in graph.edges:
                fanout[edge.upstream_endpoint] = fanout.get(edge.upstream_endpoint, 0) + 1
            for endpoint, fcount in fanout.items():
                if fcount > limits.max_fanout_per_endpoint:
                    violations.append(
                        builder.error(
                            rule="FANOUT_LIMIT_EXCEEDED",
                            endpoint=endpoint,
                            provenance=[f"graph:{graph.session_window_id}"],
                            extra={
                                "fanout": fcount,
                                "max_allowed": limits.max_fanout_per_endpoint,
                            },
                        )
                    )

            # Topology complexity score: edges / nodes ratio bounded
            if node_count > 0:
                complexity = edge_count / node_count
                if complexity > limits.max_topology_complexity_score:
                    violations.append(
                        builder.critical(
                            rule="TOPOLOGY_COMPLEXITY_GROWTH_EXCEEDED",
                            provenance=[f"graph:{graph.session_window_id}"],
                            extra={
                                "complexity_score": complexity,
                                "max_allowed": limits.max_topology_complexity_score,
                            },
                        )
                    )

        # 2. FSM depth and cardinality bounds
        max_fsm_iter = min(len(fsms), bounds.max_endpoints_per_trace)
        for fidx, fsm in enumerate(fsms[:max_fsm_iter]):
            evidence_count += 1
            if fsm.node_count() > fsm.max_nodes:
                violations.append(
                    builder.critical(
                        rule="FSM_NODE_COUNT_EXCEEDS_BOUND",
                        provenance=[f"fsm:{fsm.fsm_id}"],
                        extra={
                            "node_count": fsm.node_count(),
                            "max_allowed": fsm.max_nodes,
                        },
                    )
                )
            if fsm.edge_count() > fsm.max_edges:
                violations.append(
                    builder.critical(
                        rule="FSM_EDGE_COUNT_EXCEEDS_BOUND",
                        provenance=[f"fsm:{fsm.fsm_id}"],
                        extra={
                            "edge_count": fsm.edge_count(),
                            "max_allowed": fsm.max_edges,
                        },
                    )
                )
            for node in fsm.nodes:
                node_id = node.get("node_id", "") if isinstance(node, dict) else getattr(node, "node_id", "")
                fanout_count = fsm.fanout(node_id) if hasattr(fsm, "fanout") else 0
                if isinstance(fanout_count, int) and fanout_count > fsm.max_fanout:
                    violations.append(
                        builder.error(
                            rule="FSM_FANOUT_EXCEEDS_BOUND",
                            provenance=[f"fsm:{fsm.fsm_id}", f"node:{node_id}"],
                            extra={
                                "fanout": fanout_count,
                                "max_allowed": fsm.max_fanout,
                            },
                        )
                    )

        # 3. Auth surface expansion
        max_trace_iter = min(len(traces), bounds.max_endpoints_per_trace)
        for tidx, trace in enumerate(traces[:max_trace_iter]):
            auth_fields = [f for f in trace.fields if "auth" in f.inferred_type.lower() or f.path.lower() in ("authorization", "x-api-key", "cookie", "csrf")]
            if len(auth_fields) > limits.max_auth_fields_per_endpoint:
                violations.append(
                    builder.error(
                        rule="AUTH_SURFACE_EXPANSION_EXCEEDED",
                        endpoint=trace.endpoint_template,
                        provenance=[f"trace:{tidx}"],
                        extra={
                            "auth_field_count": len(auth_fields),
                            "max_allowed": limits.max_auth_fields_per_endpoint,
                        },
                    )
                )

        # Auth invariants unconfirmed
        unconfirmed = [inv for inv in invariants if not inv.replay_confirmed]
        if len(unconfirmed) > limits.max_unconfirmed_auth_bindings:
            violations.append(
                builder.warning(
                    rule="UNCONFIRMED_AUTH_BINDING_COUNT_HIGH",
                    extra={
                        "unconfirmed_count": len(unconfirmed),
                        "max_allowed": limits.max_unconfirmed_auth_bindings,
                    },
                )
            )

        if len(invariants) > limits.max_auth_invariants_per_graph:
            violations.append(
                builder.error(
                    rule="AUTH_INVARIANT_COUNT_EXCEEDS_LIMIT",
                    extra={
                        "invariant_count": len(invariants),
                        "max_allowed": limits.max_auth_invariants_per_graph,
                    },
                )
            )

        # 4. Replay propagation scope growth
        # Count side-effect-bound endpoints and replay scope nodes
        side_effect_endpoints = [
            trace.endpoint_template
            for trace in traces
            if self._classify_trace(trace) == "SIDE_EFFECT_BOUND"
        ]
        if len(side_effect_endpoints) > limits.max_side_effect_bound_endpoints:
            violations.append(
                builder.critical(
                    rule="REPLAY_PROPAGATION_SCOPE_GROWTH_EXCEEDED",
                    extra={
                        "side_effect_bound_count": len(side_effect_endpoints),
                        "max_allowed": limits.max_side_effect_bound_endpoints,
                    },
                )
            )

        # Replay scope node count from graphs
        total_nodes = sum(len(g.nodes) for g in dep_graphs)
        if total_nodes > limits.max_replay_scope_nodes:
            violations.append(
                builder.error(
                    rule="REPLAY_SCOPE_NODE_COUNT_EXCEEDED",
                    extra={
                        "total_nodes": total_nodes,
                        "max_allowed": limits.max_replay_scope_nodes,
                    },
                )
            )

        # Graph depth heuristic: longest simple path (bounded DFS)
        max_graph_iter = min(len(dep_graphs), bounds.max_edges_per_graph)
        for gidx, graph in enumerate(dep_graphs[:max_graph_iter]):
            depth = self._graph_depth(graph, bounds.max_blast_radius_depth)
            if depth > limits.max_replay_propagation_depth:
                violations.append(
                    builder.error(
                        rule="REPLAY_PROPAGATION_DEPTH_EXCEEDED",
                        provenance=[f"graph:{graph.session_window_id}"],
                        extra={
                            "depth": depth,
                            "max_allowed": limits.max_replay_propagation_depth,
                        },
                    )
                )

        return WorkerResponse(
            execution_id=execution_id,
            pass_name="blast_radius",
            status=WorkerStatus.SUCCESS if not violations else WorkerStatus.VERIFICATION_MISMATCH,
            violations=violations,
            evidence_count=evidence_count,
            output_hash="",
            execution_time_ms=0,
        )

    def _classify_trace(self, trace: SemanticIRTrace) -> str:
        method = trace.method
        if method in ("GET", "HEAD", "OPTIONS"):
            return "IDEMPOTENT_READ"
        if method == "DELETE":
            return "DESTRUCTIVE_MUTATION"
        if method in ("POST", "PUT", "PATCH"):
            return "STATEFUL_MUTATION"
        return "UNKNOWN"

    def _graph_depth(self, graph: DependencyGraph, max_depth: int) -> int:
        """Bounded DFS to compute longest simple path depth."""
        adj: Dict[str, List[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.upstream_endpoint, []).append(edge.downstream_endpoint)

        max_depth_found = 0
        # Iterative DFS with depth limit to prevent unbounded recursion
        for start in list(adj.keys()):
            stack: List[tuple[str, int, set[str]]] = [(start, 1, {start})]
            while stack:
                node, depth, visited = stack.pop()
                if depth > max_depth:
                    return max_depth + 1  # Exceeded bound
                if depth > max_depth_found:
                    max_depth_found = depth
                for neighbor in adj.get(node, []):
                    if neighbor not in visited:
                        new_visited = set(visited)
                        new_visited.add(neighbor)
                        stack.append((neighbor, depth + 1, new_visited))
        return max_depth_found
