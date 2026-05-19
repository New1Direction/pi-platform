"""Replay Safety Validation Pass.

Deterministic enforcement of replay governance.

Rules enforced:
  1. Production replay prohibitions (replay_unsafe / side_effect_bound)
  2. Sandbox-required routes (stateful mutations must be sandboxed)
  3. Replay mutation classifications (only idempotent/pure replayable in prod)

Consumes: SemanticIRTrace, SemanticDiff, AuthInvariant artifacts.
No inference. Only deterministic rule matching.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pi_semantic_validator.policy import ArchitecturePolicy
from pi_semantic_validator.models import (
    AuthInvariant,
    GovernanceViolation,
    ReplayClass,
    SemanticDiff,
    SemanticIRTrace,
    ValidationArtifact,
    ValidationBoundsConfig,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.violations import ViolationBuilder


class ReplaySafetyValidationPass:
    """Deterministic replay safety validator."""

    def execute(self, envelope: Dict[str, Any]) -> WorkerResponse:
        execution_id: str = envelope["execution_id"]
        artifacts: List[ValidationArtifact] = envelope["artifacts"]
        policy: ArchitecturePolicy = envelope["policy"]
        bounds: ValidationBoundsConfig = envelope["bounds"]

        builder = ViolationBuilder("replay_safety")
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

        # Build replay-confirmed endpoint set
        replay_confirmed = set()
        for inv in auth_invariants:
            if inv.replay_confirmed:
                for ep in inv.replay_confirmed_endpoints:
                    replay_confirmed.add(ep)

        max_trace_iter = min(len(traces), bounds.max_endpoints_per_trace)
        for tidx, trace in enumerate(traces[:max_trace_iter]):
            endpoint = trace.endpoint_template
            method = trace.method
            evidence_count += 1

            rule = policy.get_replay_rule_for_endpoint(endpoint, method)
            if rule is None:
                if policy.global_fail_closed:
                    violations.append(
                        builder.error(
                            rule="REPLAY_RULE_UNCLASSIFIED",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}"],
                            extra={"method": method},
                        )
                    )
                continue

            # 1. Production replay prohibition
            if rule.production_replay_prohibited:
                # Any trace that is not idempotent/pure replayable is a violation
                # if it lacks replay confirmation.
                if endpoint not in replay_confirmed:
                    violations.append(
                        builder.critical(
                            rule="PRODUCTION_REPLAY_PROHIBITED",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                            extra={
                                "method": method,
                                "required_replay_class": rule.required_replay_class,
                            },
                        )
                    )

            mutation_class = self._classify_trace(trace)

            # 2. Sandbox-required routes
            if rule.sandbox_required:
                # If sandbox is required but the trace's mutation class is not
                # in the sandbox-replayable list, flag it.
                if mutation_class not in rule.sandbox_replayable_mutations:
                    violations.append(
                        builder.error(
                            rule="SANBOX_REQUIRED_ROUTE_NOT_SANDBOX_REPLAYABLE",
                            endpoint=endpoint,
                            provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                            extra={
                                "mutation_class": mutation_class,
                                "sandbox_replayable": rule.sandbox_replayable_mutations,
                            },
                        )
                    )

            # 3. Replay mutation classification enforcement
            # The trace must match the required replay class.
            effective_replay_class = self._effective_replay_class(trace, mutation_class)
            if effective_replay_class != rule.required_replay_class:
                violations.append(
                    builder.error(
                        rule="REPLAY_CLASSIFICATION_MISMATCH",
                        endpoint=endpoint,
                        provenance=[f"trace:{tidx}", f"rule:{rule.rule_id}"],
                        extra={
                            "effective_replay_class": effective_replay_class,
                            "required_replay_class": rule.required_replay_class,
                        },
                    )
                )

        # 4. Diff-level replay equivalence enforcement
        max_diff_iter = min(len(diffs), bounds.max_endpoints_per_trace)
        for didx, diff in enumerate(diffs[:max_diff_iter]):
            evidence_count += 1
            # If replay equivalence is contested and drift score is high,
            # enforce sandbox or prohibit production replay.
            if diff.replay_equivalence == "CONTESTED":
                if diff.drift_score > policy.blast_radius_limits.max_drift_score:
                    violations.append(
                        builder.critical(
                            rule="REPLAY_CONTESTED_WITH_HIGH_DRIFT",
                            provenance=[f"diff:{didx}"],
                            extra={
                                "drift_score": diff.drift_score,
                                "replay_equivalence": diff.replay_equivalence,
                            },
                        )
                    )

        return WorkerResponse(
            execution_id=execution_id,
            pass_name="replay_safety",
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

    def _effective_replay_class(self, trace: SemanticIRTrace, mutation_class: str) -> str:
        """Deterministic mapping from mutation class to replay class."""
        if mutation_class == "IDEMPOTENT_READ":
            return ReplayClass.PURE_REPLAYABLE
        if mutation_class == "STATEFUL_MUTATION":
            return ReplayClass.IDEMPOTENT
        if mutation_class in ("DESTRUCTIVE_MUTATION", "REPLAY_UNSAFE", "SIDE_EFFECT_BOUND"):
            return ReplayClass.NON_REPLAYABLE
        return ReplayClass.SIDE_EFFECT_RISK
