"""pi-extension-governor: Main Extension Governor Pipeline.

Orchestrates the full extension admission lifecycle:
  inspect -> verify_determinism -> normalize -> evaluate_policy -> assign_trust_zone -> admit/reject

No autonomy. No recursive spawning. Deterministic only.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from pi_extension_governor.inspector import (
    CapabilityClassification,
    InspectionReport,
    StaticCapabilityInspector,
)
from pi_extension_governor.manifest import (
    ExtensionBundle,
    ExtensionManifest,
    ExtensionStatus,
)
from pi_extension_governor.normalizer import SemanticOutputNormalizer
from pi_extension_governor.policy import ExtensionGovernancePolicy, PolicyEvaluation
from pi_extension_governor.provenance import (
    ExtensionExecutionReceipt,
    ExtensionProvenanceLedger,
)
from pi_extension_governor.sandbox import SandboxRuntimeError, SandboxedExtensionRuntime
from pi_extension_governor.trust_zones import TrustZoneDecision, TrustZoneEnforcer


@dataclass(frozen=True)
class ExtensionAdmissionResult:
    manifest_id: str
    admitted: bool
    status: ExtensionStatus
    inspection_report: Optional[InspectionReport]
    determinism_verified: bool
    policy_evaluation: Optional[PolicyEvaluation]
    trust_zone_decision: Optional[TrustZoneDecision]
    normalization_result: Optional[Dict[str, Any]]
    provenance_receipt_id: Optional[str]
    reason: str


class ExtensionGovernor:
    """Central extension admission authority.

    Single authoritative gate for all external packages entering the mesh.
    """

    def __init__(
        self,
        policy: ExtensionGovernancePolicy,
        ledger: ExtensionProvenanceLedger,
        trust_enforcer: TrustZoneEnforcer,
        sandbox: Optional[SandboxedExtensionRuntime] = None,
        inspector: Optional[StaticCapabilityInspector] = None,
        normalizer: Optional[SemanticOutputNormalizer] = None,
    ) -> None:
        self.policy = policy
        self.ledger = ledger
        self.trust_enforcer = trust_enforcer
        self.sandbox = sandbox or SandboxedExtensionRuntime()
        self.inspector = inspector or StaticCapabilityInspector()
        self.normalizer = normalizer or SemanticOutputNormalizer()

    def process_bundle(self, bundle: ExtensionBundle, entrypoint_source: str, test_inputs: Dict[str, Any]) -> ExtensionAdmissionResult:
        """Full lifecycle admission processing for an extension bundle.

        Phase 1: Static inspection
        Phase 2: Determinism verification
        Phase 3: Semantic normalization
        Phase 4: Policy evaluation
        Phase 5: Trust zone assignment
        Phase 6: Admit or reject
        """
        manifest = bundle.manifest

        # Phase 1: Static inspection (only inspect the provided source, not CWD)
        source_hash = hashlib.sha256(entrypoint_source.encode()).hexdigest()
        inspection_report = InspectionReport(
            package_hash=manifest.package_hash,
            classifications=set(),
            findings=[],
            determinism_score=100,
            replay_safety_score=100,
            inspected_at=datetime.now().isoformat(),
            inspection_hash="",
        )

        # Quick AST-based source inspection
        try:
            tree = ast.parse(entrypoint_source)
            temp_inspector = StaticCapabilityInspector()
            for node in ast.walk(tree):
                temp_inspector._check_imports(node, Path("entrypoint.py"))
                temp_inspector._check_calls(node, Path("entrypoint.py"), entrypoint_source)
                temp_inspector._check_eval_exec(node, Path("entrypoint.py"))
                temp_inspector._check_file_operations(node, Path("entrypoint.py"))
                temp_inspector._check_threading(node, Path("entrypoint.py"))
            temp_inspector._apply_classification_rules()
            inspection_report = InspectionReport(
                package_hash=manifest.package_hash,
                classifications=temp_inspector.classifications,
                findings=temp_inspector.findings,
                determinism_score=temp_inspector._compute_determinism_score(),
                replay_safety_score=temp_inspector._compute_replay_safety_score(),
                inspected_at=datetime.now().isoformat(),
                inspection_hash="",
            )
        except SyntaxError:
            return ExtensionAdmissionResult(
                manifest_id=manifest.extension_id,
                admitted=False,
                status=ExtensionStatus.REJECTED,
                inspection_report=None,
                determinism_verified=False,
                policy_evaluation=None,
                trust_zone_decision=None,
                normalization_result=None,
                provenance_receipt_id=None,
                reason="Syntax error in extension entrypoint",
            )

        # Rejected by inspection = terminal
        if CapabilityClassification.REJECTED in inspection_report.classifications:
            return ExtensionAdmissionResult(
                manifest_id=manifest.extension_id,
                admitted=False,
                status=ExtensionStatus.REJECTED,
                inspection_report=inspection_report,
                determinism_verified=False,
                policy_evaluation=None,
                trust_zone_decision=None,
                normalization_result=None,
                provenance_receipt_id=None,
                reason="Static inspection rejected extension: dangerous capabilities detected",
            )

        # Phase 2: Determinism verification
        determinism_verified = self.sandbox.verify_determinism(entrypoint_source, test_inputs, runs=3)

        # Phase 3: Semantic normalization (test execution)
        sandbox_result = self.sandbox.execute(entrypoint_source, test_inputs)
        normalization_result = None
        if sandbox_result.status == "SUCCESS" and sandbox_result.output:
            normalization_result = self.normalizer.normalize(sandbox_result.output, manifest)
            if normalization_result.get("artifact_type") == "NormalizationRejection":
                return ExtensionAdmissionResult(
                    manifest_id=manifest.extension_id,
                    admitted=False,
                    status=ExtensionStatus.REJECTED,
                    inspection_report=inspection_report,
                    determinism_verified=determinism_verified,
                    policy_evaluation=None,
                    trust_zone_decision=None,
                    normalization_result=normalization_result,
                    provenance_receipt_id=None,
                    reason=f"Semantic normalization rejected: {normalization_result.get('reason')}",
                )

        # Phase 4: Policy evaluation
        policy_eval = self.policy.evaluate(manifest)

        # Phase 5: Trust zone assignment
        trust_decision = self.trust_enforcer.evaluate(manifest)

        # Phase 6: Final admission decision
        admitted = (
            determinism_verified
            and policy_eval.passed
            and trust_decision.allowed
            and CapabilityClassification.REJECTED not in inspection_report.classifications
            and sandbox_result.status == "SUCCESS"
        )

        status = ExtensionStatus.ADMITTED if admitted else ExtensionStatus.REJECTED
        reason = "Extension admitted to mesh" if admitted else "Extension failed admission criteria"
        if not determinism_verified:
            reason = "Determinism verification failed: outputs varied across runs"
        elif not policy_eval.passed:
            reason = "Policy evaluation failed: extension violates governance policy"
        elif sandbox_result.status != "SUCCESS":
            reason = f"Sandbox execution failed: {sandbox_result.status}"

        # Provenance receipt
        provenance_receipt_id = None
        if admitted:
            receipt = ExtensionExecutionReceipt(
                receipt_id=f"rcpt_{manifest.extension_id}_{__import__('uuid').uuid4().hex[:12]}",
                extension_id=manifest.extension_id,
                package_hash=manifest.package_hash,
                worker_contract_version="1.0.0",
                execution_duration_ms=sandbox_result.execution_time_ms,
                output_hash=sandbox_result.output_hash,
                deterministic_fingerprint=sandbox_result.output_hash,
                replay_lineage=[manifest.extension_id],
            )
            receipt = self.ledger.append_receipt(receipt)
            provenance_receipt_id = receipt.receipt_id

        return ExtensionAdmissionResult(
            manifest_id=manifest.extension_id,
            admitted=admitted,
            status=status,
            inspection_report=inspection_report,
            determinism_verified=determinism_verified,
            policy_evaluation=policy_eval,
            trust_zone_decision=trust_decision,
            normalization_result=normalization_result,
            provenance_receipt_id=provenance_receipt_id,
            reason=reason,
        )
