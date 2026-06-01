"""Extension Governance Policy Engine.

Org-level policy definitions for extension admission.
Deterministic rule evaluation. No inference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    TrustZone,
)


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    rule_type: str  # banned_import, max_resource, required_capability, trust_zone_restriction
    condition: Dict[str, Any]
    action: str  # ALLOW, DENY, REQUIRE_REVIEW
    severity: str  # CRITICAL, HIGH, MEDIUM


@dataclass(frozen=True)
class PolicyEvaluation:
    manifest_id: str
    passed: bool
    evaluations: List[Dict[str, Any]]
    policy_hash: str


class ExtensionGovernancePolicy:
    """Deterministic policy engine for extension admission control."""

    def __init__(
        self,
        approved_capability_classes: Optional[Set[CapabilityClass]] = None,
        banned_imports: Optional[Set[str]] = None,
        max_cpu_ms: int = 5000,
        max_memory_mb: int = 512,
        max_output_size: int = 10 * 1024 * 1024,
        require_replay_safe: bool = True,
        require_deterministic: bool = True,
        allowed_trust_zones: Optional[Set[TrustZone]] = None,
        allowed_telemetry_surfaces: Optional[Set[str]] = None,
    ) -> None:
        self.approved_capability_classes = approved_capability_classes or set(CapabilityClass)
        self.banned_imports = banned_imports or set()
        self.max_cpu_ms = max_cpu_ms
        self.max_memory_mb = max_memory_mb
        self.max_output_size = max_output_size
        self.require_replay_safe = require_replay_safe
        self.require_deterministic = require_deterministic
        self.allowed_trust_zones = allowed_trust_zones or {TrustZone.CORE_TRUSTED, TrustZone.GOVERNED_EXTENSION}
        self.allowed_telemetry_surfaces = allowed_telemetry_surfaces or set()
        self.rules = self._build_rules()

    def _build_rules(self) -> List[PolicyRule]:
        rules = [
            PolicyRule(
                "capability_class",
                "required_capability",
                {"allowed": [c.value for c in self.approved_capability_classes]},
                "ALLOW",
                "CRITICAL",
            ),
            PolicyRule(
                "resource_cpu",
                "max_resource",
                {"max": self.max_cpu_ms, "field": "resource_cpu_ms_max"},
                "DENY",
                "CRITICAL",
            ),
            PolicyRule(
                "resource_memory",
                "max_resource",
                {"max": self.max_memory_mb, "field": "resource_memory_mb_max"},
                "DENY",
                "CRITICAL",
            ),
            PolicyRule(
                "replay_safe",
                "required_capability",
                {"required": self.require_replay_safe, "field": "replayability_claim"},
                "DENY",
                "HIGH",
            ),
            PolicyRule(
                "deterministic",
                "required_capability",
                {"required": self.require_deterministic, "field": "deterministic_claim"},
                "DENY",
                "HIGH",
            ),
            PolicyRule(
                "trust_zone",
                "trust_zone_restriction",
                {"allowed": [z.value for z in self.allowed_trust_zones]},
                "DENY",
                "CRITICAL",
            ),
            PolicyRule(
                "network_access", "banned_capability", {"banned": True, "field": "network_access"}, "DENY", "HIGH"
            ),
            PolicyRule(
                "filesystem_access", "banned_capability", {"banned": True, "field": "filesystem_access"}, "DENY", "HIGH"
            ),
            PolicyRule(
                "subprocess_access",
                "banned_capability",
                {"banned": True, "field": "subprocess_access"},
                "DENY",
                "CRITICAL",
            ),
            PolicyRule(
                "dynamic_eval",
                "banned_capability",
                {"banned": True, "field": "dynamic_eval_access"},
                "DENY",
                "CRITICAL",
            ),
        ]
        return rules

    def evaluate(self, manifest: ExtensionManifest) -> PolicyEvaluation:
        """Evaluate manifest against all policy rules."""
        evaluations: List[Dict[str, Any]] = []
        passed = True

        for rule in self.rules:
            result = self._evaluate_rule(rule, manifest)
            evaluations.append(result)
            if result["action"] == "DENY" and not result["passed"]:
                passed = False

        # Hash of evaluation for provenance
        import hashlib
        import json

        policy_hash = hashlib.sha256(
            json.dumps(evaluations, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        return PolicyEvaluation(
            manifest_id=manifest.extension_id,
            passed=passed,
            evaluations=evaluations,
            policy_hash=policy_hash,
        )

    def _evaluate_rule(self, rule: PolicyRule, manifest: ExtensionManifest) -> Dict[str, Any]:
        """Evaluate a single policy rule against a manifest."""
        condition = rule.condition
        field_value = None
        passed = True
        detail = ""

        if rule.rule_type == "required_capability":
            if "allowed" in condition:
                field_value = manifest.capability_class.value
                passed = field_value in condition["allowed"]
                if not passed:
                    detail = f"Capability class '{field_value}' not in approved list"
            elif "required" in condition:
                field_name = condition["field"]
                field_value = getattr(manifest, field_name, False)
                passed = bool(field_value) == condition["required"]
                if not passed:
                    detail = f"Field '{field_name}' required={condition['required']}, actual={field_value}"

        elif rule.rule_type == "max_resource":
            field_name = condition["field"]
            field_value = getattr(manifest, field_name, 0)
            max_val = condition["max"]
            passed = field_value <= max_val
            if not passed:
                detail = f"Resource '{field_name}' value={field_value} exceeds max={max_val}"

        elif rule.rule_type == "trust_zone_restriction":
            field_value = manifest.trust_zone.value
            passed = field_value in condition["allowed"]
            if not passed:
                detail = f"Trust zone '{field_value}' not in allowed zones"

        elif rule.rule_type == "banned_capability":
            field_name = condition["field"]
            field_value = getattr(manifest, field_name, False)
            if condition["banned"]:
                passed = not bool(field_value)
            if not passed:
                detail = f"Banned capability '{field_name}' is enabled"

        return {
            "rule_id": rule.rule_id,
            "rule_type": rule.rule_type,
            "action": rule.action,
            "severity": rule.severity,
            "passed": passed,
            "field_value": field_value,
            "detail": detail,
        }
