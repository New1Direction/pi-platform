"""Core Validator Runtime.

Deterministic, bounded, replayable, evidence-linked, schema-validated,
append-only, fail-closed.

The runtime loads artifacts and policy, executes validation passes in
fixed order, and emits a PASS / FAIL / INDETERMINATE report.

No inference. No LLM calls. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pi_semantic_validator.models import (
    EpistemicState,
    GovernanceViolation,
    ValidationArtifact,
    ValidationBoundsConfig,
    ValidationReport,
    WorkerResponse,
    WorkerStatus,
)
from pi_semantic_validator.passes.blast_radius import BlastRadiusValidationPass

# Pass imports (will be wired below)
from pi_semantic_validator.passes.boundary import BoundaryValidationPass
from pi_semantic_validator.passes.layer import LayerValidationPass
from pi_semantic_validator.passes.mutation_drift import MutationDriftValidationPass
from pi_semantic_validator.passes.replay_safety import ReplaySafetyValidationPass
from pi_semantic_validator.policy import ArchitecturePolicy, load_policy
from pi_semantic_validator.violations import ViolationBuilder


class ValidatorRuntime:
    """Deterministic semantic governance worker.

    f(policy, artifacts) -> ValidationReport

    The ONLY legal execution path for semantic governance.
    """

    PASS_ORDER = [
        ("boundary", BoundaryValidationPass),
        ("layer", LayerValidationPass),
        ("mutation_drift", MutationDriftValidationPass),
        ("replay_safety", ReplaySafetyValidationPass),
        ("blast_radius", BlastRadiusValidationPass),
    ]

    def __init__(
        self,
        policy: ArchitecturePolicy,
        bounds: Optional[ValidationBoundsConfig] = None,
    ) -> None:
        self.policy = policy
        self.bounds = bounds or ValidationBoundsConfig()
        self._violations: List[GovernanceViolation] = []
        self._pass_results: Dict[str, WorkerResponse] = {}
        self._execution_id = f"val_{uuid.uuid4().hex[:12]}"

    @property
    def execution_id(self) -> str:
        return self._execution_id

    def _compute_artifacts_hash(self, artifacts: List[ValidationArtifact]) -> str:
        hashes = sorted(a.semantic_hash for a in artifacts)
        combined = "|".join(hashes)
        return hashlib.sha256(combined.encode()).hexdigest()

    def _bounded_collect(
        self,
        new_violations: List[GovernanceViolation],
        max_count: int,
    ) -> List[GovernanceViolation]:
        """Fail-closed collection: truncate with a boundary violation if exceeded."""
        if len(new_violations) > max_count:
            truncated = new_violations[:max_count]
            truncated.append(
                ViolationBuilder("runtime").critical(
                    rule="BOUNDED_EXECUTION_VIOLATION_LIMIT_EXCEEDED",
                    extra={
                        "requested_violations": len(new_violations),
                        "max_allowed": max_count,
                        "pass_name": "runtime",
                    },
                )
            )
            return truncated
        return new_violations

    def run(self, artifacts: List[ValidationArtifact]) -> ValidationReport:
        """Execute all validation passes in fixed order with bounded execution."""
        artifacts_hash = self._compute_artifacts_hash(artifacts)
        policy_hash = self.policy.compute_hash()
        start_ms = int(time.time() * 1000)

        # Pre-validate: fail-closed if no artifacts
        if not artifacts:
            self._violations.append(
                ViolationBuilder("runtime").critical(
                    rule="NO_ARTIFACTS_PROVIDED",
                    extra={"policy_hash": policy_hash},
                )
            )
            return self._assemble_report(
                artifacts_hash=artifacts_hash,
                policy_hash=policy_hash,
                elapsed_ms=int(time.time() * 1000) - start_ms,
            )

        # Execute passes in fixed order
        for pass_name, pass_cls in self.PASS_ORDER:
            pass_start = int(time.time() * 1000)
            try:
                worker = pass_cls()
                envelope = {
                    "execution_id": self._execution_id,
                    "pass_name": pass_name,
                    "artifacts": artifacts,
                    "policy": self.policy,
                    "bounds": self.bounds,
                }
                response = worker.execute(envelope)
            except Exception as exc:
                response = WorkerResponse(
                    execution_id=self._execution_id,
                    pass_name=pass_name,
                    status=WorkerStatus.FAILURE,
                    violations=[
                        ViolationBuilder(pass_name).critical(
                            rule="PASS_EXECUTION_FAILURE",
                            extra={"error": str(exc), "pass": pass_name},
                        )
                    ],
                    evidence_count=0,
                    output_hash="",
                    execution_time_ms=int(time.time() * 1000) - pass_start,
                )

            # Bounded collect
            bounded = self._bounded_collect(response.violations, self.bounds.max_violations_per_pass)
            response.violations = bounded
            self._violations.extend(bounded)
            self._pass_results[pass_name] = response

        elapsed_ms = int(time.time() * 1000) - start_ms
        return self._assemble_report(
            artifacts_hash=artifacts_hash,
            policy_hash=policy_hash,
            elapsed_ms=elapsed_ms,
        )

    def _assemble_report(
        self,
        artifacts_hash: str,
        policy_hash: str,
        elapsed_ms: int,
    ) -> ValidationReport:
        status: str = "PASS"
        if any(v.severity == "CRITICAL" for v in self._violations):
            status = "FAIL"
        elif any(v.severity == "ERROR" for v in self._violations):
            status = "FAIL"
        elif self.policy.global_fail_closed and not self._pass_results:
            # If no passes ran and fail-closed, mark INDETERMINATE
            status = "INDETERMINATE"

        summary = {
            "total_violations": len(self._violations),
            "critical_count": sum(1 for v in self._violations if v.severity == "CRITICAL"),
            "error_count": sum(1 for v in self._violations if v.severity == "ERROR"),
            "warning_count": sum(1 for v in self._violations if v.severity == "WARNING"),
            "passes_executed": len(self._pass_results),
            "execution_time_ms": elapsed_ms,
            "bounded_truncated": any(v.rule == "BOUNDED_EXECUTION_VIOLATION_LIMIT_EXCEEDED" for v in self._violations),
        }

        return ValidationReport(
            report_id=f"report_{uuid.uuid4().hex[:16]}",
            execution_id=self._execution_id,
            policy_hash=policy_hash,
            artifacts_hash=artifacts_hash,
            status=status,  # type: ignore[arg-type]
            pass_results=self._pass_results,
            violations=self._violations,
            summary=summary,
            bounds=self.bounds,
        )


def build_artifact(raw: Dict[str, Any]) -> ValidationArtifact:
    """Factory: deserialize a raw artifact dict into a ValidationArtifact.

    Fail-closed: unknown types create an artifact with type Unknown.
    """
    artifact_type_str = raw.get("artifact_type", "Unknown")
    payload = raw.get("payload", raw)
    sem_hash = raw.get("semantic_hash", "")
    if not sem_hash:
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        sem_hash = hashlib.sha256(payload_json.encode()).hexdigest()

    type_mapping = {
        "SemanticIRTrace": "SemanticIRTrace",
        "DependencyGraph": "DependencyGraph",
        "SynthesizedSpec": "SynthesizedSpec",
        "SemanticDiff": "SemanticDiff",
        "AuthInvariant": "AuthInvariant",
        "ProtocolStateMachine": "ProtocolStateMachine",
    }

    mapped_type = type_mapping.get(artifact_type_str, "Unknown")

    return ValidationArtifact(
        artifact_id=raw.get("artifact_id", f"art_{uuid.uuid4().hex[:12]}"),
        artifact_type=mapped_type,  # type: ignore[arg-type]
        payload=payload,
        semantic_hash=sem_hash,
        provenance=raw.get("provenance", []),
        epistemic_state=raw.get("epistemic_state", EpistemicState.OBSERVED),
        source_execution_id=raw.get("source_execution_id", ""),
    )


def run_validator(
    policy_path: Path | str,
    artifact_paths: List[Path | str],
    bounds: Optional[ValidationBoundsConfig] = None,
) -> ValidationReport:
    """High-level entrypoint: load policy and artifacts, run validator."""
    policy = load_policy(policy_path)

    artifacts: List[ValidationArtifact] = []
    for path in artifact_paths:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Support both single artifact and list of artifacts
        if isinstance(raw, list):
            for item in raw:
                artifacts.append(build_artifact(item))
        elif isinstance(raw, dict):
            artifacts.append(build_artifact(raw))

    runtime = ValidatorRuntime(policy=policy, bounds=bounds)
    return runtime.run(artifacts)
