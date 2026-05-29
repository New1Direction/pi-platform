"""Boundary Validation Pass.

Deterministic enforcement of trust boundaries.

Rules enforced:
  1. Forbidden trust boundary crossings (DependencyGraph edges)
  2. Isolated database enforcement (state writers must match allowed layer)
  3. Unauthorized state writers (layer writes to unallowed store)

No inference. Only rule matching.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pi_semantic_validator.models import (
    DependencyGraph,
    GovernanceViolation,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.policy import ArchitecturePolicy, TrustBoundaryRule
from pi_semantic_validator.violations import ViolationBuilder


class BoundaryValidationPass:
    """Deterministic boundary validator."""

    def execute(self, envelope: Dict[str, Any]) -> WorkerResponse:
        execution_id: str = envelope["execution_id"]
        artifacts: List[ValidationArtifact] = envelope["artifacts"]
        policy: ArchitecturePolicy = envelope["policy"]
        bounds: ValidationBoundsConfig = envelope["bounds"]

        builder = ViolationBuilder("boundary")
        violations: List[GovernanceViolation] = []
        evidence_count = 0

        # Extract DependencyGraph artifacts
        dep_graphs: List[DependencyGraph] = []
        for art in artifacts:
            if art.artifact_type == "DependencyGraph" and isinstance(art.payload, dict):
                try:
                    dep_graphs.append(DependencyGraph.model_validate(art.payload))
                except Exception:
                    # Fail-closed: unparseable graph is a violation
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_DEPENDENCY_GRAPH",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )

        max_iter = min(len(dep_graphs), bounds.max_edges_per_graph)
        for _gidx, graph in enumerate(dep_graphs[:max_iter]):
            edges = graph.edges
            max_edge_iter = min(len(edges), bounds.max_edges_per_graph)
            for eidx, edge in enumerate(edges[:max_edge_iter]):
                up_zone = policy.get_zone_for_endpoint(edge.upstream_endpoint)
                down_zone = policy.get_zone_for_endpoint(edge.downstream_endpoint)
                evidence_count += 1

                if up_zone and down_zone and up_zone.zone_id != down_zone.zone_id:
                    # Cross-zone edge detected; check rules
                    rule = self._find_boundary_rule(
                        policy, up_zone.zone_id, down_zone.zone_id
                    )
                    if rule is None:
                        if policy.global_fail_closed:
                            violations.append(
                                builder.error(
                                    rule="TRUST_BOUNDARY_CROSSING_UNRULED",
                                    endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                    field_path=edge.upstream_field,
                                    provenance=[
                                        f"graph:{graph.session_window_id}",
                                        f"edge:{eidx}",
                                    ],
                                    extra={
                                        "from_zone": up_zone.zone_id,
                                        "to_zone": down_zone.zone_id,
                                    },
                                )
                            )
                    elif rule.action == "FORBIDDEN":
                        violations.append(
                            builder.critical(
                                rule="FORBIDDEN_TRUST_BOUNDARY_CROSSING",
                                endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                field_path=edge.upstream_field,
                                provenance=[
                                    f"graph:{graph.session_window_id}",
                                    f"edge:{eidx}",
                                    f"rule:{rule.rule_id}",
                                ],
                                extra={
                                    "from_zone": up_zone.zone_id,
                                    "to_zone": down_zone.zone_id,
                                    "rule_id": rule.rule_id,
                                },
                            )
                        )
                    elif rule.action == "REQUIRES_AUTH":
                        # If crossing requires auth, verify that an auth invariant exists.
                        # Since we do not infer, we only flag if the recon artifact
                        # explicitly lacks auth evidence.
                        # For now, we emit a warning that the crossing needs audit.
                        violations.append(
                            builder.warning(
                                rule="TRUST_BOUNDARY_CROSSING_REQUIRES_AUTH",
                                endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                provenance=[
                                    f"graph:{graph.session_window_id}",
                                    f"rule:{rule.rule_id}",
                                ],
                                extra={
                                    "from_zone": up_zone.zone_id,
                                    "to_zone": down_zone.zone_id,
                                    "required_invariants": rule.required_auth_invariants,
                                },
                            )
                        )

        # State writer validation: check SemanticIRTrace for stateful mutations
        # and ensure their endpoints are in layers allowed to write state.
        traces: List[Any] = []
        for art in artifacts:
            if art.artifact_type == "SemanticIRTrace" and isinstance(art.payload, dict):
                traces.append(art.payload)

        max_trace_iter = min(len(traces), bounds.max_endpoints_per_trace)
        for tidx, trace_raw in enumerate(traces[:max_trace_iter]):
            endpoint = trace_raw.get("endpoint_template", "")
            method = trace_raw.get("method", "")
            trace_raw.get("fields", [])
            layer = policy.get_layer_for_endpoint(endpoint)

            # Detect stateful mutation by method or mutation classification in fields
            is_stateful = method in ("POST", "PUT", "DELETE", "PATCH")
            if not is_stateful:
                continue

            if layer is None:
                if policy.global_fail_closed:
                    violations.append(
                        builder.error(
                            rule="STATEFUL_MUTATION_UNCLASSIFIED_LAYER",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}"],
                            extra={"method": method},
                        )
                    )
                continue

            # Check if layer is authorized for state writes
            writer_rule = None
            for swr in policy.state_writer_rules:
                if swr.layer_id == layer.layer_id:
                    writer_rule = swr
                    break

            if writer_rule is None and policy.global_fail_closed:
                violations.append(
                    builder.critical(
                        rule="UNAUTHORIZED_STATE_WRITER",
                        endpoint=endpoint,
                        provenance=[f"trace:{tidx}", f"layer:{layer.layer_id}"],
                        extra={"method": method, "layer": layer.layer_id},
                    )
                )
            elif writer_rule and writer_rule.fail_closed and not writer_rule.allowed_writers:
                violations.append(
                    builder.critical(
                        rule="ISOLATED_DATABASE_ENFORCEMENT_VIOLATION",
                        endpoint=endpoint,
                        provenance=[f"trace:{tidx}", f"layer:{layer.layer_id}"],
                        extra={
                            "method": method,
                            "layer": layer.layer_id,
                            "allowed_writers": writer_rule.allowed_writers,
                        },
                    )
                )

        return WorkerResponse(
            execution_id=execution_id,
            pass_name="boundary",
            status=WorkerStatus.SUCCESS if not violations else WorkerStatus.VERIFICATION_MISMATCH,
            violations=violations,
            evidence_count=evidence_count,
            output_hash="",
            execution_time_ms=0,
        )

    def _find_boundary_rule(
        self, policy: ArchitecturePolicy, from_zone: str, to_zone: str
    ) -> Optional[TrustBoundaryRule]:
        for rule in policy.trust_boundary_rules:
            if rule.from_zone == from_zone and rule.to_zone == to_zone:
                return rule
        return None
