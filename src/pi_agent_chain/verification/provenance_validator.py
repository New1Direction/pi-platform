"""Provenance Validator.

Phase 1 of verification subsystem expansion.

Every semantic claim must be traceable to observed evidence.
No artifact may transition INFERRED -> VERIFIED without provenance closure.

The validator is observational ONLY. It returns GovernanceViolations.
It does NOT mutate runtime state. Only GovernanceKernel may promote epistemic states.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, List, Optional

from pi_agent_chain.models import EpistemicState, GovernanceViolation, ValidationBoundsConfig


class ProvenanceValidator:
    """Immutable truth lineage enforcer.

    Detects:
    1. orphaned artifacts
    2. unverifiable ancestry
    3. broken evidence chains
    4. replay hash mismatches
    5. epistemic contamination
    6. cyclic provenance graphs
    7. unverifiable promotions
    8. lineage tampering
    """

    def __init__(self, registry, bounds: Optional[Any] = None) -> None:
        """registry: an ArtifactRegistry instance."""
        self.registry = registry
        self.bounds = bounds or ValidationBoundsConfig()

    # ──────────────────────────────
    #  Public API
    # ──────────────────────────────

    def validate(self, artifact) -> List[GovernanceViolation]:
        """Run ALL provenance checks on a single artifact.

        Returns a list of violations. Empty list = lineage is clean.
        """
        violations: List[GovernanceViolation] = []
        seen_in_chain = set()

        violations.extend(self._check_orphaned(artifact))
        violations.extend(self._check_ancestry(artifact))
        violations.extend(self._check_broken_chains(artifact))
        violations.extend(self._check_hash_integrity(artifact))
        violations.extend(self._check_epistemic_contamination(artifact))
        violations.extend(self._check_cyclic_lineage(artifact, seen_in_chain))
        violations.extend(self._check_lineage_tampering(artifact))

        return violations

    def can_promote(self, artifact, target_state: str) -> tuple[bool, List[GovernanceViolation]]:
        """Check whether an artifact may safely be promoted to target_state.

        INFERRED -> VERIFIED requires provenance closure.
        Returns (allowed, violations).
        """
        if target_state != EpistemicState.VERIFIED:
            return True, []

        if artifact.epistemic_state != EpistemicState.INFERRED:
            return True, []

        # Core rule: all dependency chains must resolve to OBSERVED or VERIFIED
        violations = self.validate(artifact)
        if violations:
            return False, violations

        # Check closure: all ancestors are OBSERVED or VERIFIED
        closure_violations = self._check_provenance_closure(artifact)
        if closure_violations:
            return False, closure_violations

        # Check promotion evidence exists
        if not artifact.evidence_refs:
            return False, [
                self._make_violation(
                    "UNVERIFIABLE_PROMOTION",
                    artifact,
                    {"target_state": target_state, "reason": "No evidence_refs for promotion"},
                )
            ]

        return True, []

    # ──────────────────────────────
    #  Individual Checks
    # ──────────────────────────────

    def _check_orphaned(self, artifact) -> List[GovernanceViolation]:
        """Artifact with no parent_artifact_ids and no evidence_refs
        that is NOT epistemic OBSERVED is orphaned."""
        if (
            artifact.epistemic_state != EpistemicState.OBSERVED
            and not artifact.parent_artifact_ids
            and not artifact.evidence_refs
        ):
            return [
                self._make_violation(
                    "ORPHANED_ARTIFACT",
                    artifact,
                    {"epistemic_state": artifact.epistemic_state},
                )
            ]
        return []

    def _check_ancestry(self, artifact) -> List[GovernanceViolation]:
        """All parent_artifact_ids must exist in registry."""
        violations = []
        for parent_id in artifact.parent_artifact_ids:
            parent = self._find_artifact_by_id(parent_id)
            if parent is None:
                violations.append(
                    self._make_violation(
                        "UNVERIFIABLE_ANCESTRY",
                        artifact,
                        {"missing_parent_id": parent_id},
                    )
                )
        return violations

    def _check_broken_chains(self, artifact) -> List[GovernanceViolation]:
        """Evidence refs must point to actual artifacts."""
        violations = []
        for ref in artifact.evidence_refs:
            if ref.startswith("artifact:"):
                evidence_id = ref.replace("artifact:", "")
                evidence = self._find_artifact_by_id(evidence_id)
                if evidence is None:
                    violations.append(
                        self._make_violation(
                            "BROKEN_EVIDENCE_CHAIN",
                            artifact,
                            {"missing_evidence_id": evidence_id},
                        )
                    )
        return violations

    def _check_hash_integrity(self, artifact) -> List[GovernanceViolation]:
        """Replay hash consistency: payload hash must match semantic_hash."""
        if not artifact.payload_json:
            return [
                self._make_violation(
                    "REPLAY_HASH_MISMATCH",
                    artifact,
                    {"reason": "Empty payload_json"},
                )
            ]

        computed = hashlib.sha256(artifact.payload_json.encode()).hexdigest()
        if computed != artifact.semantic_hash:
            return [
                self._make_violation(
                    "REPLAY_HASH_MISMATCH",
                    artifact,
                    {"computed": computed, "stored": artifact.semantic_hash},
                )
            ]

        # Check input/output/trace hash consistency if they exist
        if artifact.input_hash and artifact.output_hash:
            combined = hashlib.sha256(f"{artifact.input_hash}:{artifact.output_hash}".encode()).hexdigest()
            if artifact.trace_hash and combined != artifact.trace_hash:
                return [
                    self._make_violation(
                        "REPLAY_HASH_MISMATCH",
                        artifact,
                        {"computed_trace": combined, "stored_trace": artifact.trace_hash},
                    )
                ]
        return []

    def _check_epistemic_contamination(self, artifact) -> List[GovernanceViolation]:
        """An OBSERVED artifact must NOT have INFERRED ancestors.
        An artifact cannot claim OBSERVED while being derived from INFERRED parents."""
        if artifact.epistemic_state != EpistemicState.OBSERVED:
            return []

        for parent_id in artifact.parent_artifact_ids:
            parent = self._find_artifact_by_id(parent_id)
            if parent and parent.epistemic_state == EpistemicState.INFERRED:
                return [
                    self._make_violation(
                        "EPISTEMIC_CONTAMINATION",
                        artifact,
                        {
                            "artifact_state": artifact.epistemic_state,
                            "parent_state": parent.epistemic_state,
                            "parent_id": parent_id,
                        },
                    )
                ]
        return []

    def _check_cyclic_lineage(self, artifact, seen: set, depth: int = 0) -> List[GovernanceViolation]:
        """Detect circular parent references."""
        if depth > 20:
            # Safety cap - cycle likely if depth exceeds 20
            return [
                self._make_violation(
                    "CYCLIC_PROVENANCE",
                    artifact,
                    {"depth_reached": depth, "seen": list(seen)},
                )
            ]

        if artifact.artifact_id in seen:
            return [
                self._make_violation(
                    "CYCLIC_PROVENANCE",
                    artifact,
                    {"cycle_at": artifact.artifact_id, "path": list(seen)},
                )
            ]

        seen.add(artifact.artifact_id)
        violations = []
        for parent_id in artifact.parent_artifact_ids:
            parent = self._find_artifact_by_id(parent_id)
            if parent:
                violations.extend(self._check_cyclic_lineage(parent, seen.copy(), depth + 1))
        return violations

    def _check_lineage_tampering(self, artifact) -> List[GovernanceViolation]:
        """Detect signs that provenance metadata was modified post-creation.
        Simple heuristic: if promotion records exist but parent_artifact_ids
        don't include the original source, suspicious."""
        # Check for promotion records in provenance string list
        has_promotion = any(p.startswith("promoted:") for p in artifact.provenance)
        if has_promotion and not artifact.parent_artifact_ids and not artifact.evidence_refs:
            return [
                self._make_violation(
                    "LINEAGE_TAMPERING",
                    artifact,
                    {"reason": "Promoted artifact with no parents or evidence"},
                )
            ]
        return []

    def _check_provenance_closure(self, artifact) -> List[GovernanceViolation]:
        """Core rule: all dependency chains must resolve to OBSERVED or VERIFIED artifacts only.
        No dangling INFERRED nodes in the ancestry."""
        violations = []
        visited = set()

        def _walk(art, depth: int = 0):
            if depth > 20:
                violations.append(
                    self._make_violation(
                        "ANCESTRY_DEPTH_EXCEEDED",
                        art,
                        {"max_depth": 20},
                    )
                )
                return
            if art.artifact_id in visited:
                return
            visited.add(art.artifact_id)

            if art.epistemic_state in {EpistemicState.OBSERVED, EpistemicState.VERIFIED}:
                return  # Terminal - valid root

            if art.epistemic_state == EpistemicState.INFERRED:
                # Must have parents that can close
                if not art.parent_artifact_ids:
                    violations.append(
                        self._make_violation(
                            "PROVENANCE_NOT_CLOSED",
                            art,
                            {"reason": "INFERRED artifact with no parents"},
                        )
                    )
                    return

            for parent_id in art.parent_artifact_ids:
                parent = self._find_artifact_by_id(parent_id)
                if parent is None:
                    violations.append(
                        self._make_violation(
                            "PROVENANCE_NOT_CLOSED",
                            art,
                            {"missing_parent": parent_id},
                        )
                    )
                    continue
                _walk(parent, depth + 1)

        _walk(artifact)
        return violations

    # ──────────────────────────────
    #  Helpers
    # ──────────────────────────────

    def _find_artifact_by_id(self, artifact_id: str):
        """Search all artifacts for a matching artifact_id."""
        # ArtifactRegistry doesn't have a find_by_id method, so scan
        for art in self.registry.all_artifacts():
            if art.artifact_id == artifact_id:
                return art
        return None

    def _make_violation(self, rule: str, artifact, context: dict) -> GovernanceViolation:
        return GovernanceViolation(
            violation_id=hashlib.sha256(
                f"{rule}:{artifact.artifact_id}:{json.dumps(context, sort_keys=True)}".encode()
            ).hexdigest()[:16],
            rule=rule,
            worker_id=artifact.generated_by,
            root_goal_id="provenance_validator",
            severity="CRITICAL",
            context={
                "artifact_id": artifact.artifact_id,
                "artifact_type": artifact.artifact_type,
                **context,
            },
            action_taken="HALT",
        )
