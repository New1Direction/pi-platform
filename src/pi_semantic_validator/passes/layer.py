"""Layer Validation Pass.

Deterministic enforcement of architectural layering.

Rules enforced:
  1. Forbidden imports (layer A imports from layer B where rule says FORBIDDEN)
  2. Runtime layering violations (endpoint served by wrong layer)
  3. Backend/frontend inversion detection (frontend calls backend directly)

No inference. Only rule matching against layer definitions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pi_semantic_validator.models import (
    DependencyGraph,
    GovernanceViolation,
    SemanticIRTrace,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.policy import ArchitecturePolicy
from pi_semantic_validator.violations import ViolationBuilder


class LayerValidationPass:
    """Deterministic layer validator."""

    def execute(self, envelope: Dict[str, Any]) -> WorkerResponse:
        execution_id: str = envelope["execution_id"]
        artifacts: List[ValidationArtifact] = envelope["artifacts"]
        policy: ArchitecturePolicy = envelope["policy"]
        bounds: ValidationBoundsConfig = envelope["bounds"]

        builder = ViolationBuilder("layer")
        violations: List[GovernanceViolation] = []
        evidence_count = 0

        # Collect traces and graphs
        traces: List[SemanticIRTrace] = []
        for art in artifacts:
            if art.artifact_type == "SemanticIRTrace" and isinstance(art.payload, dict):
                try:
                    traces.append(SemanticIRTrace.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_SEMANTIC_TRACE",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )

        graphs: List[DependencyGraph] = []
        for art in artifacts:
            if art.artifact_type == "DependencyGraph" and isinstance(art.payload, dict):
                try:
                    graphs.append(DependencyGraph.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_DEPENDENCY_GRAPH",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )

        # 1. Runtime layering violations: endpoint assigned to layer, but trace
        #    metadata (generated_by) indicates mismatch. Since we cannot infer
        #    code location from traces alone, we validate that every endpoint
        #    matches at least one layer definition.
        max_trace_iter = min(len(traces), bounds.max_endpoints_per_trace)
        for tidx, trace in enumerate(traces[:max_trace_iter]):
            layer = policy.get_layer_for_endpoint(trace.endpoint_template)
            evidence_count += 1
            if layer is None and policy.global_fail_closed:
                violations.append(
                    builder.error(
                        rule="RUNTIME_LAYERING_UNCLASSIFIED",
                        endpoint=trace.endpoint_template,
                        provenance=[f"trace:{tidx}"],
                        extra={"method": trace.method, "generated_by": trace.generated_by},
                    )
                )

        # 2. Forbidden imports / backend-frontend inversion via graph edges
        #    We treat upstream -> downstream as an import/call direction.
        max_graph_iter = min(len(graphs), bounds.max_edges_per_graph)
        for _gidx, graph in enumerate(graphs[:max_graph_iter]):
            max_edge_iter = min(len(graph.edges), bounds.max_edges_per_graph)
            for eidx, edge in enumerate(graph.edges[:max_edge_iter]):
                up_layer = policy.get_layer_for_endpoint(edge.upstream_endpoint)
                down_layer = policy.get_layer_for_endpoint(edge.downstream_endpoint)
                evidence_count += 1
                if up_layer and down_layer and up_layer.layer_id != down_layer.layer_id:
                    rule = self._find_layer_rule(policy, up_layer.layer_id, down_layer.layer_id)
                    if rule is None:
                        if policy.global_fail_closed:
                            violations.append(
                                builder.error(
                                    rule="LAYER_CROSSING_UNRULED",
                                    endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                    provenance=[f"graph:{graph.session_window_id}", f"edge:{eidx}"],
                                    extra={
                                        "from_layer": up_layer.layer_id,
                                        "to_layer": down_layer.layer_id,
                                    },
                                )
                            )
                    elif rule.action == "FORBIDDEN":
                        violations.append(
                            builder.critical(
                                rule="FORBIDDEN_LAYER_IMPORT",
                                endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                provenance=[
                                    f"graph:{graph.session_window_id}",
                                    f"edge:{eidx}",
                                    f"rule:{rule.rule_id}",
                                ],
                                extra={
                                    "from_layer": up_layer.layer_id,
                                    "to_layer": down_layer.layer_id,
                                    "rule_id": rule.rule_id,
                                },
                            )
                        )
                    elif rule.action == "REQUIRES_GATEWAY":
                        # Fail-closed: if no gateway module is listed, it's a violation
                        if not rule.gateway_modules:
                            violations.append(
                                builder.critical(
                                    rule="LAYER_GATEWAY_REQUIRED_BUT_NONE_CONFIGURED",
                                    endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                    provenance=[
                                        f"graph:{graph.session_window_id}",
                                        f"edge:{eidx}",
                                        f"rule:{rule.rule_id}",
                                    ],
                                    extra={
                                        "from_layer": up_layer.layer_id,
                                        "to_layer": down_layer.layer_id,
                                    },
                                )
                            )

        # 3. Backend/frontend inversion: if a frontend layer endpoint is
        #    downstream of a backend layer endpoint, that is inversion.
        for _gidx, graph in enumerate(graphs[:max_graph_iter]):
            max_edge_iter = min(len(graph.edges), bounds.max_edges_per_graph)
            for eidx, edge in enumerate(graph.edges[:max_edge_iter]):
                up_layer = policy.get_layer_for_endpoint(edge.upstream_endpoint)
                down_layer = policy.get_layer_for_endpoint(edge.downstream_endpoint)
                if up_layer and down_layer:
                    if up_layer.layer_id in down_layer.forbidden_importers:
                        violations.append(
                            builder.critical(
                                rule="BACKEND_FRONTEND_INVERSION_DETECTED",
                                endpoint=f"{edge.upstream_endpoint} -> {edge.downstream_endpoint}",
                                provenance=[
                                    f"graph:{graph.session_window_id}",
                                    f"edge:{eidx}",
                                ],
                                extra={
                                    "upstream_layer": up_layer.layer_id,
                                    "downstream_layer": down_layer.layer_id,
                                    "forbidden_importers": down_layer.forbidden_importers,
                                },
                            )
                        )

        # 4. Forbidden imports from policy forbidden_import_rules
        for fir in policy.forbidden_import_rules:
            layer = None
            for l in policy.layers:
                if l.layer_id == fir.layer_id:
                    layer = l
                    break
            if layer is None:
                continue
            # Since we don't have source code imports in artifacts, we flag
            # as a policy audit notice (warning) that the rule exists but
            # cannot be verified without source-level artifacts.
            violations.append(
                builder.warning(
                    rule="FORBIDDEN_IMPORT_RULE_UNVERIFIABLE_NO_SOURCE_ARTIFACTS",
                    extra={
                        "layer_id": fir.layer_id,
                        "forbidden_modules": fir.forbidden_modules,
                        "is_critical": fir.is_critical,
                    },
                )
            )

        return WorkerResponse(
            execution_id=execution_id,
            pass_name="layer",
            status=WorkerStatus.SUCCESS if not violations else WorkerStatus.VERIFICATION_MISMATCH,
            violations=violations,
            evidence_count=evidence_count,
            output_hash="",
            execution_time_ms=0,
        )

    def _find_layer_rule(
        self, policy: ArchitecturePolicy, from_layer: str, to_layer: str
    ) -> Optional[Any]:
        for rule in policy.layer_rules:
            if rule.from_layer == from_layer and rule.to_layer == to_layer:
                return rule
        return None
