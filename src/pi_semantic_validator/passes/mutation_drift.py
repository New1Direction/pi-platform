"""Mutation Drift Validation Pass.

Deterministic enforcement of mutation classification stability.

Rules enforced:
  1. READ_ONLY -> STATEFUL_MUTATION detection (method drift)
  2. Destructive mutation escalation (DELETE/PUT without replay_unsafe)
  3. Auth requirement drift (stateful mutation without auth invariant)

Consumes: SemanticIRTrace, SemanticDiff, AuthInvariant artifacts.
No inference. Only pattern matching against policy.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pi_semantic_validator.models import (
    AuthInvariant,
    GovernanceViolation,
    SemanticDiff,
    SemanticIRTrace,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.policy import ArchitecturePolicy
from pi_semantic_validator.violations import ViolationBuilder


class MutationDriftValidationPass:
    """Deterministic mutation drift validator."""

    def execute(self, envelope: Dict[str, Any]) -> WorkerResponse:
        execution_id: str = envelope["execution_id"]
        artifacts: List[ValidationArtifact] = envelope["artifacts"]
        policy: ArchitecturePolicy = envelope["policy"]
        bounds: ValidationBoundsConfig = envelope["bounds"]

        builder = ViolationBuilder("mutation_drift")
        violations: List[GovernanceViolation] = []
        evidence_count = 0

        traces: List[SemanticIRTrace] = []
        diffs: List[SemanticDiff] = []
        auth_invariants: List[AuthInvariant] = []

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
            elif art.artifact_type == "SemanticDiff" and isinstance(art.payload, dict):
                try:
                    diffs.append(SemanticDiff.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_SEMANTIC_DIFF",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )
            elif art.artifact_type == "AuthInvariant" and isinstance(art.payload, dict):
                try:
                    auth_invariants.append(AuthInvariant.model_validate(art.payload))
                except Exception:
                    violations.append(
                        builder.critical(
                            rule="UNPARSEABLE_AUTH_INVARIANT",
                            extra={"artifact_id": art.artifact_id},
                        )
                    )

        # Build auth endpoint coverage map
        auth_endpoint_set = set()
        for inv in auth_invariants:
            for ep in inv.affected_endpoints:
                auth_endpoint_set.add(ep)

        # 1. Trace-level mutation classification vs policy
        max_trace_iter = min(len(traces), bounds.max_endpoints_per_trace)
        for tidx, trace in enumerate(traces[:max_trace_iter]):
            endpoint = trace.endpoint_template
            method = trace.method
            evidence_count += 1

            rule = policy.get_mutation_rule_for_endpoint(endpoint, method)
            if rule is None:
                if policy.global_fail_closed:
                    violations.append(
                        builder.error(
                            rule="MUTATION_RULE_UNCLASSIFIED",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}"],
                            extra={"method": method},
                        )
                    )
                continue

            # Determine actual mutation class from trace fields and method
            actual_class = self._classify_trace(trace)
            if actual_class not in rule.allowed_mutation_classes:
                violations.append(
                    builder.critical(
                        rule="MUTATION_CLASS_POLICY_VIOLATION",
                        endpoint=endpoint,
                        provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                        extra={
                            "method": method,
                            "actual_class": actual_class,
                            "allowed_classes": rule.allowed_mutation_classes,
                        },
                    )
                )

            # 2. Destructive mutation escalation
            if actual_class in ("DESTRUCTIVE_MUTATION", "REPLAY_UNSAFE"):
                if rule.requires_replay_unsafe_for_destructive and actual_class != "REPLAY_UNSAFE":
                    violations.append(
                        builder.critical(
                            rule="DESTRUCTIVE_MUTATION_REQUIRES_REPLAY_UNSAFE",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                            extra={"actual_class": actual_class},
                        )
                    )

            # 3. Auth requirement drift
            if rule.requires_auth_for_mutation and actual_class in (
                "STATEFUL_MUTATION",
                "DESTRUCTIVE_MUTATION",
                "REPLAY_UNSAFE",
            ):
                if endpoint not in auth_endpoint_set:
                    violations.append(
                        builder.error(
                            rule="STATEFUL_MUTATION_MISSING_AUTH_INVARIANT",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                            extra={"actual_class": actual_class},
                        )
                    )

        # 4. Diff-level drift detection
        max_diff_iter = min(len(diffs), bounds.max_endpoints_per_trace)
        for didx, diff in enumerate(diffs[:max_diff_iter]):
            evidence_count += 1
            # Structural delta exceeding policy limit
            if diff.structural_delta_score > policy.blast_radius_limits.max_structural_delta_score:
                violations.append(
                    builder.error(
                        rule="STRUCTURAL_DELTA_EXCEEDS_LIMIT",
                        provenance=[f"diff:{didx}"],
                        extra={
                            "structural_delta_score": diff.structural_delta_score,
                            "max_allowed": policy.blast_radius_limits.max_structural_delta_score,
                        },
                    )
                )
            # Semantic delta exceeding policy limit
            if diff.semantic_delta_score > policy.blast_radius_limits.max_semantic_delta_score:
                violations.append(
                    builder.error(
                        rule="SEMANTIC_DELTA_EXCEEDS_LIMIT",
                        provenance=[f"diff:{didx}"],
                        extra={
                            "semantic_delta_score": diff.semantic_delta_score,
                            "max_allowed": policy.blast_radius_limits.max_semantic_delta_score,
                        },
                    )
                )
            # Auth mutations
            if len(diff.auth_mutations) > policy.blast_radius_limits.max_auth_mutation_count:
                violations.append(
                    builder.critical(
                        rule="AUTH_MUTATION_COUNT_EXCEEDS_LIMIT",
                        provenance=[f"diff:{didx}"],
                        extra={
                            "auth_mutations": diff.auth_mutations,
                            "count": len(diff.auth_mutations),
                            "max_allowed": policy.blast_radius_limits.max_auth_mutation_count,
                        },
                    )
                )
            # Drift score
            if diff.drift_score > policy.blast_radius_limits.max_drift_score:
                violations.append(
                    builder.error(
                        rule="DRIFT_SCORE_EXCEEDS_LIMIT",
                        provenance=[f"diff:{didx}"],
                        extra={
                            "drift_score": diff.drift_score,
                            "max_allowed": policy.blast_radius_limits.max_drift_score,
                        },
                    )
                )

        return WorkerResponse(
            execution_id=execution_id,
            pass_name="mutation_drift",
            status=WorkerStatus.SUCCESS if not violations else WorkerStatus.VERIFICATION_MISMATCH,
            violations=violations,
            evidence_count=evidence_count,
            output_hash="",
            execution_time_ms=0,
        )

    def _classify_trace(self, trace: SemanticIRTrace) -> str:
        """Deterministic classification of a trace's mutation behavior.

        No inference. Based solely on method and trace metadata.
        """
        method = trace.method
        if method in ("GET", "HEAD", "OPTIONS"):
            return "IDEMPOTENT_READ"
        if method == "DELETE":
            return "DESTRUCTIVE_MUTATION"
        if method in ("POST", "PUT", "PATCH"):
            # Could be stateful or side-effect bound; default to stateful
            # unless metadata explicitly says otherwise (not inferred)
            return "STATEFUL_MUTATION"
        return "UNKNOWN"
