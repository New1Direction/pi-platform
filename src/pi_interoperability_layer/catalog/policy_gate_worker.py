"""Package Policy Gate Worker.

Applies ExtensionGovernancePolicy rules to external catalog packages.
Deterministic pass/fail with evidence. No inference.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import List, Optional, Set, Tuple

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    TrustZone,
)
from pi_extension_governor.policy import ExtensionGovernancePolicy


@dataclass(frozen=True)
class PolicyGateFinding:
    rule_id: str
    rule_type: str
    passed: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    evidence: str


@dataclass(frozen=True)
class PackagePolicyGateResult:
    manifest_id: str
    passed: bool
    findings: Tuple[PolicyGateFinding, ...]
    gate_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "manifest_id": self.manifest_id,
                "passed": self.passed,
                "findings": [
                    {
                        "rule": f.rule_id,
                        "type": f.rule_type,
                        "passed": f.passed,
                        "severity": f.severity,
                        "evidence": f.evidence,
                    }
                    for f in self.findings
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class PackagePolicyGateWorker:
    """Deterministic policy gate for external catalog packages.

    Evaluates ExtensionManifest against org-level policy.
    Outputs: PASS/FAIL with evidence-bound findings.
    """

    def __init__(self, policy: Optional[ExtensionGovernancePolicy] = None) -> None:
        self.policy = policy or self._default_policy()

    def evaluate(self, manifest: ExtensionManifest) -> PackagePolicyGateResult:
        findings: List[PolicyGateFinding] = []
        passed = True

        # Rule 1: Capability class approved
        cap_ok = manifest.capability_class in self.policy.approved_capability_classes
        findings.append(PolicyGateFinding(
            rule_id="capability_class_approved",
            rule_type="required_capability",
            passed=cap_ok,
            severity="CRITICAL" if not cap_ok else "LOW",
            evidence=f"Class {manifest.capability_class.value} {'approved' if cap_ok else 'NOT in approved set'}",
        ))
        if not cap_ok:
            passed = False

        # Rule 2: Banned imports check
        banned_found: Set[str] = set()
        for dep in manifest.dependencies:
            for banned in self.policy.banned_imports:
                if banned in dep.lower():
                    banned_found.add(banned)
        ban_ok = len(banned_found) == 0
        findings.append(PolicyGateFinding(
            rule_id="banned_imports",
            rule_type="banned_import",
            passed=ban_ok,
            severity="CRITICAL" if not ban_ok else "LOW",
            evidence=f"Banned matches: {sorted(banned_found)}" if banned_found else "No banned imports detected",
        ))
        if not ban_ok:
            passed = False

        # Rule 3: Trust zone restriction
        zone_ok = manifest.trust_zone in self.policy.allowed_trust_zones
        findings.append(PolicyGateFinding(
            rule_id="trust_zone_allowed",
            rule_type="trust_zone_restriction",
            passed=zone_ok,
            severity="HIGH" if not zone_ok else "LOW",
            evidence=f"Zone {manifest.trust_zone.value} {'allowed' if zone_ok else 'NOT allowed'}",
        ))
        if not zone_ok:
            passed = False

        # Rule 4: Telemetry surface restriction
        telemetry_ok = all(
            surf in self.policy.allowed_telemetry_surfaces
            for surf in manifest.telemetry_surfaces
        ) if manifest.telemetry_surfaces else True
        findings.append(PolicyGateFinding(
            rule_id="telemetry_surfaces",
            rule_type="telemetry_restriction",
            passed=telemetry_ok,
            severity="HIGH" if not telemetry_ok else "LOW",
            evidence=f"Telemetry surfaces: {manifest.telemetry_surfaces}",
        ))
        if not telemetry_ok:
            passed = False

        # Rule 5: Replay safety requirement
        if self.policy.require_replay_safe:
            replay_ok = manifest.replayability_claim
            findings.append(PolicyGateFinding(
                rule_id="replay_safe_required",
                rule_type="replay_safety",
                passed=replay_ok,
                severity="CRITICAL" if not replay_ok else "LOW",
                evidence=f"replayability_claim={manifest.replayability_claim}",
            ))
            if not replay_ok:
                passed = False

        # Rule 6: Determinism requirement
        if self.policy.require_deterministic:
            det_ok = manifest.deterministic_claim
            findings.append(PolicyGateFinding(
                rule_id="deterministic_required",
                rule_type="determinism",
                passed=det_ok,
                severity="CRITICAL" if not det_ok else "LOW",
                evidence=f"deterministic_claim={manifest.deterministic_claim}",
            ))
            if not det_ok:
                passed = False

        # Rule 7: Resource bounds
        res_ok = manifest.resource_cpu_ms_max <= self.policy.max_cpu_ms
        findings.append(PolicyGateFinding(
            rule_id="resource_bounds",
            rule_type="max_resource",
            passed=res_ok,
            severity="HIGH" if not res_ok else "LOW",
            evidence=f"resource_cpu_ms_max={manifest.resource_cpu_ms_max} vs policy_max={self.policy.max_cpu_ms}",
        ))
        if not res_ok:
            passed = False

        result = PackagePolicyGateResult(
            manifest_id=manifest.extension_id,
            passed=passed,
            findings=tuple(findings),
            gate_hash="",
        )
        return PackagePolicyGateResult(
            manifest_id=result.manifest_id,
            passed=result.passed,
            findings=result.findings,
            gate_hash=result.compute_hash(),
        )

    @staticmethod
    def _default_policy() -> ExtensionGovernancePolicy:
        return ExtensionGovernancePolicy(
            approved_capability_classes=set(CapabilityClass),
            banned_imports={"eval", "child_process", "vm", "net", "os", "fs"},
            max_cpu_ms=10000,
            max_memory_mb=512,
            max_output_size=50 * 1024 * 1024,
            require_replay_safe=False,  # sandbox validation proves this
            require_deterministic=False,  # sandbox validation proves this
            allowed_trust_zones={TrustZone.SANDBOX_EXPERIMENTAL, TrustZone.GOVERNED_EXTENSION},
            allowed_telemetry_surfaces=set(),
        )
