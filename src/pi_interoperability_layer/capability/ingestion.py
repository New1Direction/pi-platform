"""Governed Package Ingestion Pipeline.

Deterministic admission control for external extensions entering the semantic mesh.
Connects extension governor, capability registry, and compatibility graph.
No inference. No autonomy.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.governor import ExtensionGovernor
from pi_extension_governor.manifest import (
    ExtensionBundle,
)
from pi_interoperability_layer.capability.graph import (
    CompatibilityCheck,
    CompatibilityEdge,
    CompatibilityType,
    CompatibilityVerdict,
    ExtensionCompatibilityGraph,
)
from pi_interoperability_layer.capability.registry import (
    RegistryEntryStatus,
    RegistryFingerprints,
    SemanticCapabilityRegistry,
    TrustScore,
    TrustScoringBasis,
)


class IngestionPhase(Enum):
    INSPECT = "inspect"
    DETERMINISM = "determinism"
    NORMALIZE = "normalize"
    POLICY = "policy"
    REGISTER = "register"
    COMPATIBILITY = "compatibility"
    ADMIT = "admit"


@dataclass(frozen=True)
class IngestionStep:
    phase: IngestionPhase
    passed: bool
    evidence: str = ""
    artifacts: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IngestionReceipt:
    bundle_id: str
    steps: Tuple[IngestionStep, ...]
    final_verdict: str  # "ADMITTED" | "REJECTED"
    entry_id: Optional[str] = None
    compatibility_checks: Tuple[CompatibilityCheck, ...] = field(default_factory=tuple)
    receipt_hash: str = ""
    previous_receipt_hash: str = ""

    def compute_hash(self) -> str:
        payload = (
            f"{self.bundle_id}:"
            f"{''.join(s.phase.value + ('1' if s.passed else '0') for s in self.steps)}:"
            f"{self.final_verdict}:{self.previous_receipt_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class GovernedIngestionPipeline:
    """Deterministic ingestion pipeline.

    Receives an ExtensionBundle + entrypoint source,
    runs governor phases, registers into capability registry,
    checks compatibility graph, and emits an IngestionReceipt.
    """

    def __init__(
        self,
        governor: ExtensionGovernor,
        registry: SemanticCapabilityRegistry,
        graph: ExtensionCompatibilityGraph,
        policy: Optional[Any] = None,
    ):
        self.governor = governor
        self.registry = registry
        self.graph = graph
        self.policy = policy
        self._receipts: List[IngestionReceipt] = []

    def ingest(
        self,
        bundle: ExtensionBundle,
        entrypoint_source: str,
        inputs: Dict[str, Any],
    ) -> IngestionReceipt:
        steps: List[IngestionStep] = []
        manifest = bundle.manifest

        # Phase 1: Governor static inspection + determinism + normalization + policy
        governor_result = self.governor.process_bundle(bundle, entrypoint_source, inputs)
        steps.append(
            IngestionStep(
                phase=IngestionPhase.INSPECT,
                passed=governor_result.admitted or "inspection rejected" not in governor_result.reason.lower(),
                evidence=governor_result.reason,
            )
        )
        steps.append(
            IngestionStep(
                phase=IngestionPhase.DETERMINISM,
                passed=governor_result.determinism_verified,
                evidence="determinism verified"
                if governor_result.determinism_verified
                else "determinism check failed or skipped",
            )
        )
        steps.append(
            IngestionStep(
                phase=IngestionPhase.NORMALIZE,
                passed=governor_result.normalization_result is not None,
                evidence="normalized" if governor_result.normalization_result else "normalization failed or skipped",
            )
        )
        steps.append(
            IngestionStep(
                phase=IngestionPhase.POLICY,
                passed=governor_result.policy_evaluation is not None,
                evidence="policy evaluated" if governor_result.policy_evaluation else "policy rejected or skipped",
            )
        )

        if not governor_result.admitted:
            receipt = self._build_receipt(
                bundle_id=manifest.extension_id,
                steps=steps,
                final_verdict="REJECTED",
                entry_id=None,
                compatibility_checks=(),
            )
            self._receipts.append(receipt)
            return receipt

        # Phase 2: Register into capability registry
        fingerprints = RegistryFingerprints(
            manifest_hash=manifest.compute_hash(),
            source_hash=hashlib.sha256(entrypoint_source.encode()).hexdigest(),
            determinism_fingerprint=governor_result.determinism_verified
            and hashlib.sha256("deterministic".encode()).hexdigest()
            or hashlib.sha256("non_deterministic".encode()).hexdigest(),
            policy_hash=governor_result.policy_evaluation
            and hashlib.sha256(str(governor_result.policy_evaluation).encode()).hexdigest()
            or "",
            normalization_hash=governor_result.normalization_result
            and hashlib.sha256(str(governor_result.normalization_result).encode()).hexdigest()
            or "",
            provenance_chain_hash=governor_result.provenance_receipt_id
            and hashlib.sha256(governor_result.provenance_receipt_id.encode()).hexdigest()
            or "",
        )

        trust_score = (
            TrustScore()
            .with_evidence(TrustScoringBasis.POLICY_EVIDENCE, 25)
            .with_evidence(TrustScoringBasis.DETERMINISM_PROOF, 25 if governor_result.determinism_verified else 0)
            .with_evidence(TrustScoringBasis.STATIC_ANALYSIS, 25)
        )

        previous = self.registry.lookup(manifest.extension_id)
        entry = self.registry.register(
            manifest=manifest,
            fingerprints=fingerprints,
            trust_score=trust_score,
            status=RegistryEntryStatus.ACTIVE,
            previous_entry_hash=previous.entry_hash if previous else "",
        )
        steps.append(IngestionStep(phase=IngestionPhase.REGISTER, passed=True, evidence=entry.entry_hash))

        # Phase 3: Compatibility graph check
        compat_checks = self.graph.check_install(
            extension_id=manifest.extension_id,
            manifest=manifest,
            registry_lookup=self.registry.lookup,
        )
        compat_pass = all(c.verdict == CompatibilityVerdict.COMPATIBLE for c in compat_checks)
        steps.append(
            IngestionStep(
                phase=IngestionPhase.COMPATIBILITY,
                passed=compat_pass,
                evidence=f"{len(compat_checks)} checks",
            )
        )

        if not compat_pass:
            # Rollback registration
            self.registry.update_status(manifest.extension_id, RegistryEntryStatus.REVOKED)
            receipt = self._build_receipt(
                bundle_id=manifest.extension_id,
                steps=steps,
                final_verdict="REJECTED",
                entry_id=entry.extension_id,
                compatibility_checks=tuple(compat_checks),
            )
            self._receipts.append(receipt)
            return receipt

        # Phase 4: Admit into graph
        self.graph.register_installed(manifest.extension_id)
        # If manifest declares outputs as capabilities, add edges
        for output in manifest.declared_outputs:
            edge = CompatibilityEdge(
                source_id=manifest.extension_id,
                target_id=output,
                edge_type=CompatibilityType.PROVIDES_CAPABILITY,
                reason=output,
            )
            self.graph.declare_edge(edge)

        receipt = self._build_receipt(
            bundle_id=manifest.extension_id,
            steps=steps,
            final_verdict="ADMITTED",
            entry_id=entry.extension_id,
            compatibility_checks=tuple(compat_checks),
        )
        self._receipts.append(receipt)
        return receipt

    def _build_receipt(
        self,
        bundle_id: str,
        steps: List[IngestionStep],
        final_verdict: str,
        entry_id: Optional[str],
        compatibility_checks: Tuple[CompatibilityCheck, ...],
    ) -> IngestionReceipt:
        prev_hash = self._receipts[-1].receipt_hash if self._receipts else ""
        receipt = IngestionReceipt(
            bundle_id=bundle_id,
            steps=tuple(steps),
            final_verdict=final_verdict,
            entry_id=entry_id,
            compatibility_checks=compatibility_checks,
            previous_receipt_hash=prev_hash,
        )
        object.__setattr__(receipt, "receipt_hash", receipt.compute_hash())
        return receipt

    def verify_receipt_chain(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        for i, receipt in enumerate(self._receipts):
            if receipt.receipt_hash != receipt.compute_hash():
                errors.append(f"Receipt {i} hash mismatch")
            if i > 0 and receipt.previous_receipt_hash != self._receipts[i - 1].receipt_hash:
                errors.append(f"Receipt {i} chain break")
        return len(errors) == 0, errors

    def audit_log(self) -> List[str]:
        return [f"{r.bundle_id} {r.final_verdict} {r.receipt_hash}" for r in self._receipts]
