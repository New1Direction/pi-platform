"""Catalog Integration Pipeline.

Deterministic end-to-end pipeline for catalog package admission:
  catalog ingest → classify → policy gate → sandbox validate
  → normalize → dependency expand → registry → compatibility graph

No execution autonomy. Evidence-bound at every step.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    ExtensionStatus,
)
from pi_extension_governor.policy import ExtensionGovernancePolicy
from pi_interoperability_layer.capability.graph import ExtensionCompatibilityGraph
from pi_interoperability_layer.capability.registry import (
    RegistryEntryStatus,
    RegistryFingerprints,
    SemanticCapabilityRegistry,
    TrustScore,
    TrustScoringBasis,
)
from pi_interoperability_layer.catalog.classifier_worker import (
    CapabilityClassificationResult,
    CapabilityClassifierWorker,
)
from pi_interoperability_layer.catalog.dependency_expansion_worker import (
    DependencyExpansionReceipt,
    DependencyGraphExpansionWorker,
)
from pi_interoperability_layer.catalog.ingest_worker import (
    CatalogIngestReceipt,
    PackageCatalogIngestWorker,
)
from pi_interoperability_layer.catalog.normalization_worker import (
    PackageNormalizationReceipt,
    PackageNormalizationWorker,
)
from pi_interoperability_layer.catalog.policy_gate_worker import (
    PackagePolicyGateResult,
    PackagePolicyGateWorker,
)
from pi_interoperability_layer.catalog.sandbox_worker import (
    SandboxValidationReceipt,
    SandboxValidationWorker,
)


@dataclass(frozen=True)
class CatalogPipelineReceipt:
    """Immutable receipt for full catalog pipeline execution."""

    pipeline_id: str
    manifest_id: str
    ingest_receipt_hash: str
    classification_hash: str
    policy_gate_hash: str
    sandbox_hash: str
    normalization_hash: str
    dependency_expansion_hash: str
    final_status: str  # ADMITTED, REJECTED, PENDING_REVIEW
    final_verdict: str
    evidence_chain: Tuple[str, ...]
    pipeline_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "pipeline_id": self.pipeline_id,
                "manifest_id": self.manifest_id,
                "ingest": self.ingest_receipt_hash,
                "classify": self.classification_hash,
                "policy": self.policy_gate_hash,
                "sandbox": self.sandbox_hash,
                "normalize": self.normalization_hash,
                "deps": self.dependency_expansion_hash,
                "status": self.final_status,
                "verdict": self.final_verdict,
                "evidence": sorted(self.evidence_chain),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class CatalogIntegrationPipeline:
    """Deterministic catalog integration pipeline.

    Orchestrates the full admission lifecycle for external catalog packages:
      1. Ingest from Notte catalog
      2. Classify capability
      3. Policy gate evaluation
      4. Sandbox validation (proves determinism + replay safety)
      5. Semantic normalization
      6. Dependency graph expansion
      7. Registry registration

    Every step produces an immutable receipt.
    Pipeline fails closed on any critical gate failure.
    """

    def __init__(
        self,
        registry: SemanticCapabilityRegistry,
        compatibility_graph: ExtensionCompatibilityGraph,
        policy: Optional[ExtensionGovernancePolicy] = None,
    ) -> None:
        self.registry = registry
        self.graph = compatibility_graph
        self.ingest_worker = PackageCatalogIngestWorker()
        self.classifier = CapabilityClassifierWorker()
        self.policy_gate = PackagePolicyGateWorker(policy)
        self.sandbox_worker = SandboxValidationWorker()
        self.normalizer = PackageNormalizationWorker()
        self.dependency_expander = DependencyGraphExpansionWorker(compatibility_graph)

    def process_package(
        self,
        package_name: str,
        entrypoint_source: str,
        test_inputs: Dict[str, Any],
    ) -> CatalogPipelineReceipt:
        """Run the full deterministic pipeline on a single catalog package.

        Returns an immutable pipeline receipt with the final admission verdict.
        """
        evidence: List[str] = []

        # Phase 1: Ingest
        ingest_receipt = self.ingest_worker.ingest_package(package_name)
        evidence.append(f"ingest:{ingest_receipt.ingest_id}")
        manifest = ingest_receipt.normalized_manifests[0]

        # Phase 2: Classify
        classification = self.classifier.classify(manifest)
        evidence.append(f"classify:{classification.assigned_class.value}")
        # Update manifest with classified capability class
        manifest = manifest.model_copy(update={"capability_class": classification.assigned_class})

        # Phase 3: Policy Gate
        gate_result = self.policy_gate.evaluate(manifest)
        evidence.append(f"policy:{('PASS' if gate_result.passed else 'FAIL')}")

        if not gate_result.passed:
            # Fail closed
            self._register_rejected(manifest, "Policy gate failure")
            return self._build_receipt(
                manifest,
                ingest_receipt,
                classification,
                gate_result,
                None,
                None,
                None,
                "REJECTED",
                "Policy gate failed",
                evidence,
            )

        # Phase 4: Sandbox Validation
        sandbox_receipt = self.sandbox_worker.validate(manifest, entrypoint_source, test_inputs)
        evidence.append(f"sandbox:{('PASS' if sandbox_receipt.determinism_verified else 'FAIL')}")

        if not sandbox_receipt.determinism_verified:
            self._register_rejected(manifest, "Sandbox determinism failure")
            return self._build_receipt(
                manifest,
                ingest_receipt,
                classification,
                gate_result,
                sandbox_receipt,
                None,
                None,
                "REJECTED",
                "Sandbox determinism not verified",
                evidence,
            )

        # Update manifest with proven sandbox results
        manifest = manifest.model_copy(
            update={
                "deterministic_claim": sandbox_receipt.determinism_verified,
                "replayability_claim": sandbox_receipt.replay_safe_verified,
            }
        )

        # Phase 5: Semantic Normalization
        # Use sandbox output as the raw output to normalize
        raw_output = {"artifact_type": "SemanticIRTrace", "sandbox_output": sandbox_receipt.output_hash}
        norm_receipt = self.normalizer.normalize(manifest, raw_output)
        evidence.append(f"normalize:{('PASS' if norm_receipt.normalized else 'FAIL')}")

        if not norm_receipt.normalized:
            self._register_rejected(manifest, "Normalization failure")
            return self._build_receipt(
                manifest,
                ingest_receipt,
                classification,
                gate_result,
                sandbox_receipt,
                norm_receipt,
                None,
                "REJECTED",
                "Normalization failed",
                evidence,
            )

        # Phase 6: Dependency Graph Expansion
        # Build known manifests map from registry
        known_manifests = self._build_known_manifests_map()
        dep_receipt = self.dependency_expander.expand(manifest, known_manifests)
        evidence.append(f"deps:{dep_receipt.edges_added} edges, {dep_receipt.conflicts_detected} conflicts")

        if dep_receipt.conflicts_detected > 0:
            self._register_rejected(manifest, "Dependency conflicts detected")
            return self._build_receipt(
                manifest,
                ingest_receipt,
                classification,
                gate_result,
                sandbox_receipt,
                norm_receipt,
                dep_receipt,
                "REJECTED",
                "Dependency conflicts in compatibility graph",
                evidence,
            )

        # Phase 7: Registry Registration
        fingerprints = RegistryFingerprints(
            manifest_hash=manifest.compute_hash(),
            source_hash=sandbox_receipt.output_hash if sandbox_receipt else "",
            determinism_fingerprint=sandbox_receipt.output_hash
            if sandbox_receipt and sandbox_receipt.determinism_verified
            else "",
            policy_hash=gate_result.gate_hash if gate_result else "",
            normalization_hash=norm_receipt.receipt_hash if norm_receipt else "",
            provenance_chain_hash=ingest_receipt.receipt_hash if ingest_receipt else "",
        )
        trust_score = TrustScore()
        if gate_result and gate_result.passed:
            trust_score = trust_score.with_evidence(TrustScoringBasis.POLICY_EVIDENCE, 20)
        if sandbox_receipt and sandbox_receipt.determinism_verified:
            trust_score = trust_score.with_evidence(TrustScoringBasis.DETERMINISM_PROOF, 25)
        if sandbox_receipt and sandbox_receipt.replay_safe_verified:
            trust_score = trust_score.with_evidence(TrustScoringBasis.REPLAY_VERIFICATION, 25)
        self.registry.register(
            manifest=manifest,
            fingerprints=fingerprints,
            trust_score=trust_score,
            status=RegistryEntryStatus.ACTIVE,
        )
        evidence.append("registry:ACTIVE")

        return self._build_receipt(
            manifest,
            ingest_receipt,
            classification,
            gate_result,
            sandbox_receipt,
            norm_receipt,
            dep_receipt,
            "ADMITTED",
            "All pipeline phases passed",
            evidence,
        )

    def _register_rejected(self, manifest: ExtensionManifest, reason: str) -> None:
        """Register a rejected package in the registry for audit."""
        fingerprints = RegistryFingerprints(
            manifest_hash=manifest.compute_hash(),
            source_hash="",
            determinism_fingerprint="",
            policy_hash="",
            normalization_hash="",
            provenance_chain_hash="",
        )
        trust_score = TrustScore()
        self.registry.register(
            manifest=manifest,
            fingerprints=fingerprints,
            trust_score=trust_score,
            status=RegistryEntryStatus.REVOKED,
        )

    def _build_known_manifests_map(self) -> Dict[str, ExtensionManifest]:
        """Build a map of known manifest names → ExtensionManifest from registry."""
        result: Dict[str, ExtensionManifest] = {}
        entries = self.registry.query()
        for entry in entries:
            # manifest_snapshot is stored as JSON string
            try:
                snapshot = json.loads(entry.manifest_snapshot)
                # Reconstruct minimal manifest for dependency matching
                manifest = ExtensionManifest(
                    extension_id=entry.extension_id,
                    name=entry.name,
                    version=entry.version,
                    capability_class=entry.capability_class or CapabilityClass.STATIC_ANALYSIS,
                    description="",
                    entrypoint="",
                    dependencies=snapshot.get("dependencies", []),
                    trust_zone=entry.trust_zone,
                    telemetry_surfaces=[],
                    max_execution_ms=5000,
                    replay_safe=False,
                    deterministic=False,
                    metadata={},
                    status=ExtensionStatus.ADMITTED,
                    rejection_reason=None,
                )
                result[entry.name] = manifest
            except Exception:
                continue
        return result

    def _build_receipt(
        self,
        manifest: ExtensionManifest,
        ingest: CatalogIngestReceipt,
        classification: CapabilityClassificationResult,
        gate: PackagePolicyGateResult,
        sandbox: Optional[SandboxValidationReceipt],
        normalize: Optional[PackageNormalizationReceipt],
        deps: Optional[DependencyExpansionReceipt],
        status: str,
        verdict: str,
        evidence: List[str],
    ) -> CatalogPipelineReceipt:
        receipt = CatalogPipelineReceipt(
            pipeline_id=f"pipe_{manifest.extension_id}_{ingest.raw_hash[:12]}",
            manifest_id=manifest.extension_id,
            ingest_receipt_hash=ingest.receipt_hash,
            classification_hash=classification.classification_hash,
            policy_gate_hash=gate.gate_hash,
            sandbox_hash=sandbox.receipt_hash if sandbox else "",
            normalization_hash=normalize.receipt_hash if normalize else "",
            dependency_expansion_hash=deps.receipt_hash if deps else "",
            final_status=status,
            final_verdict=verdict,
            evidence_chain=tuple(evidence),
            pipeline_hash="",
        )
        return CatalogPipelineReceipt(
            pipeline_id=receipt.pipeline_id,
            manifest_id=receipt.manifest_id,
            ingest_receipt_hash=receipt.ingest_receipt_hash,
            classification_hash=receipt.classification_hash,
            policy_gate_hash=receipt.policy_gate_hash,
            sandbox_hash=receipt.sandbox_hash,
            normalization_hash=receipt.normalization_hash,
            dependency_expansion_hash=receipt.dependency_expansion_hash,
            final_status=receipt.final_status,
            final_verdict=receipt.final_verdict,
            evidence_chain=receipt.evidence_chain,
            pipeline_hash=receipt.compute_hash(),
        )
