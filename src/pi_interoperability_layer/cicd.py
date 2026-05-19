"""CI/CD Governance Integration.

GitHub Actions integration, PR gating, artifact verification,
replay validation gates, policy enforcement hooks.

No autonomous CI behavior. No speculative gate decisions.
All gating is deterministic and evidence-bound.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ──────────────────────────────
#  GitHub Actions Integration
# ──────────────────────────────

class GitHubActionsWorkflow(BaseModel):
    """Deterministic GitHub Actions workflow definition for governance gates."""

    workflow_id: str
    name: str
    # Trigger events
    on_events: List[str] = Field(default_factory=list)
    # Job definitions
    jobs: Dict[str, Any] = Field(default_factory=dict)
    # Policy reference
    policy_ref: str = ""
    # Required artifact contracts
    required_contracts: List[str] = Field(default_factory=list)
    # Fail-closed: if True, any validation failure blocks merge
    fail_closed: bool = True
    model_config = {"frozen": True}

    def generate_yaml(self) -> str:
        """Generate deterministic GitHub Actions workflow YAML."""
        lines: List[str] = [
            f"name: {self.name}",
            "on:",
        ]
        for event in self.on_events:
            lines.append(f"  {event}:")
            lines.append("    branches: [main]")
        lines.append("jobs:")
        for job_id, job_def in self.jobs.items():
            lines.append(f"  {job_id}:")
            for key, value in job_def.items():
                if isinstance(value, list):
                    lines.append(f"    {key}:")
                    for item in value:
                        lines.append(f"      - {item}")
                elif isinstance(value, dict):
                    lines.append(f"    {key}:")
                    for k2, v2 in value.items():
                        lines.append(f"      {k2}: {v2}")
                else:
                    lines.append(f"    {key}: {value}")
        return "\n".join(lines)


# ──────────────────────────────
#  PR Gating
# ──────────────────────────────

class PRGateResult(BaseModel):
    """Deterministic result of a PR gate evaluation."""

    gate_id: str
    pr_number: int
    # Overall gate status
    status: Literal["PASS", "FAIL", "BLOCKED", "INDETERMINATE"]
    # Per-check results
    checks: Dict[str, str] = Field(default_factory=dict)
    # Violations detected
    violations: List[str] = Field(default_factory=list)
    # Artifact fingerprints verified
    artifact_fingerprints: List[str] = Field(default_factory=list)
    # Replay verification status
    replay_verified: bool = False
    # Deterministic hash of the gate inputs
    gate_hash: str = ""
    model_config = {"frozen": True}


class PRGateConfig(BaseModel):
    """Configuration for deterministic PR gating."""

    gate_id: str
    # Required validation passes that must pass
    required_passes: List[str] = Field(default_factory=list)
    # Required artifact contracts
    required_artifacts: List[str] = Field(default_factory=list)
    # Replay validation required
    require_replay_verification: bool = True
    # Policy drift check required
    require_policy_drift_check: bool = True
    # Fail-closed
    fail_closed: bool = True
    model_config = {"frozen": True}

    def evaluate(self, results: Dict[str, Any]) -> PRGateResult:
        """Evaluate PR gate deterministically."""
        checks: Dict[str, str] = {}
        violations: List[str] = []

        for required in self.required_passes:
            result = results.get(required)
            if result is None:
                checks[required] = "MISSING"
                violations.append(f"Required pass {required} missing")
            elif not result:
                checks[required] = "FAIL"
                violations.append(f"Required pass {required} failed")
            else:
                checks[required] = "PASS"

        for artifact in self.required_artifacts:
            fp = results.get(f"artifact_{artifact}")
            if not fp:
                checks[f"artifact_{artifact}"] = "MISSING"
                violations.append(f"Required artifact {artifact} missing")
            else:
                checks[f"artifact_{artifact}"] = "VERIFIED"

        replay_ok = results.get("replay_verified", False)
        if self.require_replay_verification and not replay_ok:
            checks["replay_verification"] = "FAIL"
            violations.append("Replay verification failed")
        else:
            checks["replay_verification"] = "PASS" if replay_ok else "SKIPPED"

        drift_ok = results.get("policy_drift_check", True)
        if self.require_policy_drift_check and not drift_ok:
            checks["policy_drift"] = "FAIL"
            violations.append("Policy drift detected")
        else:
            checks["policy_drift"] = "PASS" if drift_ok else "SKIPPED"

        # Gate hash
        payload = json.dumps(results, sort_keys=True, separators=(",", ":"), default=str)
        gate_hash = hashlib.sha256(payload.encode()).hexdigest()

        # Status assembly
        if violations and self.fail_closed:
            status = "BLOCKED"
        elif violations:
            status = "FAIL"
        elif all(c == "PASS" or c == "VERIFIED" or c == "SKIPPED" for c in checks.values()):
            status = "PASS"
        else:
            status = "INDETERMINATE"

        return PRGateResult(
            gate_id=self.gate_id,
            pr_number=results.get("pr_number", 0),
            status=status,  # type: ignore[arg-type]
            checks=checks,
            violations=violations,
            artifact_fingerprints=results.get("artifact_fingerprints", []),
            replay_verified=replay_ok,
            gate_hash=gate_hash,
        )


# ──────────────────────────────
#  Artifact Verification
# ──────────────────────────────

class ArtifactVerificationResult(BaseModel):
    """Deterministic artifact verification outcome."""

    artifact_id: str
    contract_id: str
    # Schema version match
    version_match: bool = False
    # Fingerprint verified
    fingerprint_verified: bool = False
    # Provenance chain verified
    provenance_verified: bool = False
    # Replay evidence present
    replay_evidence_present: bool = False
    # Overall status
    status: Literal["VERIFIED", "MISMATCH", "MISSING_CONTRACT", "MISSING_EVIDENCE"]
    model_config = {"frozen": True}


# ──────────────────────────────
#  Replay Validation Gate
# ──────────────────────────────

class ReplayValidationGate(BaseModel):
    """Deterministic replay validation gate for CI/CD."""

    gate_id: str
    # Required replay ledger ID
    required_ledger_id: str = ""
    # Minimum sequence number that must be replay-verified
    min_verified_sequence: int = 0
    # Allowed replay classes
    allowed_replay_classes: List[str] = Field(default_factory=list)
    # Sandbox required
    sandbox_required: bool = True
    # Production replay prohibited
    production_replay_prohibited: bool = True
    model_config = {"frozen": True}

    def evaluate(self, ledger_summary: Dict[str, Any]) -> Literal["PASS", "FAIL", "BLOCKED"]:
        """Evaluate replay gate deterministically."""
        if ledger_summary.get("ledger_id") != self.required_ledger_id:
            return "BLOCKED"
        if ledger_summary.get("last_verified_sequence", 0) < self.min_verified_sequence:
            return "FAIL"
        replay_class = ledger_summary.get("replay_class", "UNKNOWN")
        if replay_class not in self.allowed_replay_classes:
            return "BLOCKED"
        if self.sandbox_required and not ledger_summary.get("sandboxed", False):
            return "BLOCKED"
        if self.production_replay_prohibited and ledger_summary.get("production_replay", False):
            return "BLOCKED"
        return "PASS"


# ──────────────────────────────
#  Policy Enforcement Hooks
# ──────────────────────────────

class PolicyEnforcementHook(BaseModel):
    """Deterministic hook for policy enforcement in CI/CD pipelines."""

    hook_id: str
    hook_type: Literal[
        "PRE_MERGE",
        "POST_MERGE",
        "PRE_DEPLOY",
        "POST_DEPLOY",
        "ARTIFACT_UPLOAD",
        "SCHEMA_MIGRATION",
    ]
    # Policy file reference
    policy_ref: str = ""
    # Required validation passes
    required_validations: List[str] = Field(default_factory=list)
    # Required artifact contracts
    required_contracts: List[str] = Field(default_factory=list)
    # Notification targets on failure
    notify_on_failure: List[str] = Field(default_factory=list)
    # Fail-closed
    fail_closed: bool = True
    model_config = {"frozen": True}

    def check_required(self, context: Dict[str, Any]) -> List[str]:
        """Return list of missing requirements."""
        missing: List[str] = []
        for validation in self.required_validations:
            if not context.get(f"validation_{validation}"):
                missing.append(f"validation:{validation}")
        for contract in self.required_contracts:
            if not context.get(f"contract_{contract}"):
                missing.append(f"contract:{contract}")
        return missing
