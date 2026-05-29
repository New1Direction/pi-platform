"""Semantic Quorum — Phase 5 of verification subsystem.

Evidence-Weighted Semantic Intersection Engine.

Key constraints:
- NOT majority voting. Evidence-weighted intersection.
- Every claim MUST retain full provenance artifact/trace/packet bindings.
- Operates on INTERSECTIONS only. Never expands semantic surface area.
- Authority hierarchy: replay(1.0) > provenance(0.8) > multi‐trace(0.6) > single‐trace(0.4) > LLM(0.2)
- Contradictions preserved as explicit conflict structures. Never auto‐resolved.
- Bounded execution. Overflow => HALT.
- Entropy must monotonically decrease.
- Observational only. Never mutates runtime state.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from pi_agent_chain.artifact_registry import ArtifactRegistry, SemanticArtifact
from pi_agent_chain.models import (
    EpistemicState,
    GovernanceViolation,
    QuorumPromotionRule,
    SemanticClaim,
    SemanticConflictSet,
    SemanticField,
    SemanticIntersection,
    SemanticIRTrace,
    SemanticQuorumReport,
    ValidationBoundsConfig,
)


class SemanticQuorum:
    """Evidence-weighted intersection of semantic claims.

    NOT consensus-by-majority. Deterministic, governance-bound reduction
    of ambiguity across multiple traces and artifacts.
    """

    MAX_PROMOTION_DEPTH = 4

    def __init__(self, bounds: Optional[Any] = None):
        self.bounds = bounds or ValidationBoundsConfig()

    # Epistemic authority weight map (constitutional, not learned)
    AUTHORITY_WEIGHTS = {
        "REPLAY_CONFIRMED": 1.0,
        "PROVENANCE_COMPLETE": 0.8,
        "MULTI_TRACE_CONSISTENT": 0.6,
        "SINGLE_TRACE_OBSERVED": 0.4,
        "LLM_INFERRED": 0.2,
    }

    # Promotion rules (deterministic, monotonic)
    PROMOTION_RULES: List[QuorumPromotionRule] = [
        QuorumPromotionRule(
            rule_type="PROMOTE",
            from_state=EpistemicState.OBSERVED,
            to_state=EpistemicState.INFERRED,
            min_authority_weight=0.4,
            requires_replay=False,
            requires_provenance_closure=False,
            min_confidence=0.6,
            max_confidence_regrowth=0.05,
        ),
        QuorumPromotionRule(
            rule_type="PROMOTE",
            from_state=EpistemicState.INFERRED,
            to_state=EpistemicState.REPLAY_CONFIRMED,
            min_authority_weight=0.8,
            requires_replay=True,
            requires_provenance_closure=True,
            min_confidence=0.87,
            max_confidence_regrowth=0.0,
        ),
        QuorumPromotionRule(
            rule_type="CONTEST",
            from_state=EpistemicState.INFERRED,
            to_state=EpistemicState.CONTESTED,
            min_authority_weight=0.0,
            requires_replay=False,
            requires_provenance_closure=False,
            min_confidence=0.0,
            max_confidence_regrowth=0.0,
        ),
        QuorumPromotionRule(
            rule_type="REJECT",
            from_state=EpistemicState.INFERRED,
            to_state=EpistemicState.REJECTED,
            min_authority_weight=0.0,
            requires_replay=False,
            requires_provenance_closure=False,
            min_confidence=0.0,
            max_confidence_regrowth=0.0,
        ),
    ]

    # ──────────────────────────────
    #  Public API: execute(artifacts[, execution_id])
    # ──────────────────────────────

    def execute(
        self,
        artifacts: List[SemanticArtifact],
        execution_id: str = "",
        registry: Optional[ArtifactRegistry] = None,
    ) -> SemanticQuorumReport:
        """Execute semantic quorum over artifact set.

        1. Extract evidence-bound claims from artifacts.
        2. Intersect claims by property_path.
        3. Detect conflicts (do NOT resolve — create conflict sets).
        4. Apply deterministic promotion rules.
        5. Enforce entropy monotonicity.
        6. Emit violations on bound overflow or entropy regression.

        Returns observational report. GovernanceKernel decides action.
        """
        violations: List[GovernanceViolation] = []

        # Step 1: Extract claims from artifacts
        claims = self._extract_claims(artifacts, execution_id)
        if len(claims) > self.bounds.max_quorum_claims:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"claim_overflow:{execution_id}"),
                    rule="QUORUM_MAX_CLAIMS_EXCEEDED",
                    worker_id="semantic_quorum",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"observed_claims": len(claims), "max_claims": self.bounds.max_quorum_claims},
                    action_taken="TRUNCATE",
                )
            )
            claims = claims[: self.bounds.max_quorum_claims]

        entropy_before = self._compute_claim_entropy(claims)

        # Step 2: Group claims by property_path
        claims_by_path: Dict[str, List[SemanticClaim]] = defaultdict(list)
        for c in claims:
            claims_by_path[c.property_path].append(c)

        # Step 3: Intersect and detect conflicts
        intersections: List[SemanticIntersection] = []
        conflict_sets: List[SemanticConflictSet] = []
        rejected_claims: List[SemanticClaim] = []

        for path, path_claims in claims_by_path.items():
            if len(intersections) >= self.bounds.max_quorum_intersections or len(conflict_sets) >= self.bounds.max_quorum_conflict_sets:
                violations.append(
                    GovernanceViolation(
                        violation_id=self._hash(f"intersection_overflow:{execution_id}"),
                        rule="QUORUM_INTERSECTION_OVERFLOW",
                        worker_id="semantic_quorum",
                        root_goal_id=execution_id,
                        severity="ERROR",
                        context={
                            "intersections": len(intersections),
                            "max_intersections": self.bounds.max_quorum_intersections,
                            "conflict_sets": len(conflict_sets),
                            "max_conflict_sets": self.bounds.max_quorum_conflict_sets,
                        },
                        action_taken="TRUNCATE",
                    )
                )
                break

            inter, cs = self._intersect(path, path_claims, execution_id, rejected_claims)
            if inter is not None:
                intersections.append(inter)
            if cs is not None:
                conflict_sets.append(cs)

        # Step 4: Deterministic promotion review
        promotions = self._promote(intersections, conflict_sets, execution_id, registry)

        # Step 5: Entropy validation
        remaining_claims = self._collect_post_quorum_claims(intersections, conflict_sets, rejected_claims)
        entropy_after = self._compute_claim_entropy(remaining_claims)
        entropy_delta = entropy_after - entropy_before

        if entropy_after > entropy_before + 0.001:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"entropy_reg:{execution_id}"),
                    rule="SEMANTIC_ENTROPY_REGRESSION",
                    worker_id="semantic_quorum",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={
                        "entropy_before": round(entropy_before, 6),
                        "entropy_after": round(entropy_after, 6),
                        "entropy_delta": round(entropy_delta, 6),
                    },
                    action_taken="HALT",
                )
            )

        return SemanticQuorumReport(
            report_id=self._hash(f"quorum:{execution_id}"),
            execution_id=execution_id,
            claims=claims,
            intersections=intersections,
            conflict_sets=conflict_sets,
            rejected_claims=rejected_claims,
            promotions=promotions,
            entropy_before=round(entropy_before, 6),
            entropy_after=round(entropy_after, 6),
            entropy_delta=round(entropy_delta, 6),
            violations=violations,
            quorum_reached=bool(intersections) and not violations,
            max_depth_hit=len(promotions) >= self.MAX_PROMOTION_DEPTH,
            bounded_truncated=(len(claims) == self.bounds.max_quorum_claims or len(intersections) == self.bounds.max_quorum_intersections),
        )

    # ──────────────────────────────
    #  Claim Extraction
    # ──────────────────────────────

    def _extract_claims(
        self,
        artifacts: List[SemanticArtifact],
        execution_id: str,
    ) -> List[SemanticClaim]:
        """Extract evidence-bound SemanticClaim from artifacts that carry SemanticIRTrace."""
        claims: List[SemanticClaim] = []
        for artifact in artifacts:
            if artifact.artifact_type != "SemanticIRTrace":
                continue
            try:
                payload_data = json.loads(artifact.payload_json) if isinstance(artifact.payload_json, str) else artifact.payload_json
                trace = SemanticIRTrace(**payload_data)
            except (TypeError, json.JSONDecodeError):
                continue

            for field in trace.fields or []:
                # Derive authority from artifact state
                source_state = artifact.epistemic_state or EpistemicState.INFERRED
                replay_confirmed = source_state == EpistemicState.REPLAY_CONFIRMED
                authority = self._compute_authority(source_state, field)
                provenance = [artifact.artifact_id, trace.endpoint_template]
                claim = SemanticClaim(
                    claim_id=self._hash(f"claim:{artifact.artifact_id}:{field.inferred_type}:{field.path}"),
                    property_path=field.path,
                    semantic_type=field.inferred_type,
                    confidence_score=field.confidence,
                    artifact_id=artifact.artifact_id,
                    trace_id=trace.endpoint_template,  # use endpoint_template as trace proxy
                    packet_id="",
                    worker_id=artifact.generated_by,
                    source_epistemic_state=source_state,
                    replay_confirmed=replay_confirmed,
                    provenance_chain=provenance,
                    authority_weight=round(authority, 4),
                )
                claims.append(claim)
        return claims

    # ──────────────────────────────
    #  Intersection Engine
    # ──────────────────────────────

    def _intersect(
        self,
        property_path: str,
        claims: List[SemanticClaim],
        execution_id: str,
        rejected_sink: List[SemanticClaim],
    ) -> Tuple[Optional[SemanticIntersection], Optional[SemanticConflictSet]]:
        """Compute intersection of claims on a single property_path.

        Returns:
            (intersection, conflict_set) — only one can be non-None.

        Rules:
        - If all valid claims agree on type → intersection.
        - If any valid claim disagrees on type → entire path becomes conflict set.
        - If only one valid claim → identity intersection.
        """
        if not claims:
            return None, None

        # Reject claims below min-evidence threshold (LLM_INFERRED with low confidence)
        valid = [c for c in claims if c.authority_weight >= 0.4]
        rejected = [c for c in claims if c.authority_weight < 0.4]
        rejected_sink.extend(rejected)

        if not valid:
            return None, None

        if len(valid) == 1:
            c = valid[0]
            return SemanticIntersection(
                intersection_id=self._hash(f"inter:{execution_id}:{property_path}"),
                property_path=property_path,
                intersected_type=c.semantic_type,
                intersected_confidence=round(c.confidence_score, 4),
                agreement_claim_ids=[c.claim_id],
                total_authority_sum=round(c.authority_weight, 4),
                consensus_replay_confirmed=c.replay_confirmed,
            ), None

        # Multiple claims: strict type consensus required for intersection
        types = {c.semantic_type for c in valid}
        if len(types) == 1:
            # All agree — create intersection
            total_auth = sum(c.authority_weight for c in valid)
            min_conf = min(c.confidence_score for c in valid)
            all_replay = all(c.replay_confirmed for c in valid)
            return SemanticIntersection(
                intersection_id=self._hash(f"inter:{execution_id}:{property_path}:{list(types)[0]}"),
                property_path=property_path,
                intersected_type=list(types)[0],
                intersected_confidence=round(min_conf, 4),
                agreement_claim_ids=[c.claim_id for c in valid],
                total_authority_sum=round(total_auth, 4),
                consensus_replay_confirmed=all_replay,
            ), None

        # Disagreement detected — entire path becomes conflict set
        conflict = self._build_conflict_set(property_path, valid, execution_id)
        return None, conflict

    # ──────────────────────────────
    #  Conflict Set Builder
    # ──────────────────────────────

    def _build_conflict_set(
        self,
        property_path: str,
        residuals: List[SemanticClaim],
        execution_id: str,
    ) -> SemanticConflictSet:
        """Create explicit conflict structure. Never collapse into blended summary."""
        types = {c.semantic_type for c in residuals}
        max_conf = max(c.confidence_score for c in residuals)

        if len(types) > 1:
            conflict_type = "TYPE_MISMATCH"
            desc = f"Conflicting types {types} at path {property_path}. Preserved. Not resolved."
        elif len({c.authority_weight for c in residuals}) > 1:
            conflict_type = "AUTHORITY_WEIGHT_COLLISION"
            desc = f"Same type but authority-weight divergence at path {property_path}."
        else:
            conflict_type = "CONFIDENCE_REGRESSION"
            desc = f"Same type with confidence decay at path {property_path}."

        return SemanticConflictSet(
            conflict_id=self._hash(f"conflict:{execution_id}:{property_path}"),
            property_path=property_path,
            conflicting_claim_ids=[c.claim_id for c in residuals],
            conflict_type=conflict_type,
            description=desc,
            epistemic_state=EpistemicState.CONTESTED,
            max_confidence=round(max_conf, 4),
        )

    # ──────────────────────────────
    #  Promotion Engine
    # ──────────────────────────────

    def _promote(
        self,
        intersections: List[SemanticIntersection],
        conflict_sets: List[SemanticConflictSet],
        execution_id: str,
        registry: Optional[ArtifactRegistry],
    ) -> List[Dict[str, Any]]:
        """Apply deterministic constitutional promotion rules.

        Monotonic. No probabilistic resolution.
        """
        promotions: List[Dict[str, Any]] = []
        for inter in intersections:
            # Try REPLAY_CONFIRMED promotion first (highest authority)
            replay_rule = next(
                (r for r in self.PROMOTION_RULES if r.from_state == EpistemicState.OBSERVED and r.to_state == EpistemicState.INFERRED),
                None,
            )
            if replay_rule and inter.total_authority_sum >= replay_rule.min_authority_weight:
                # Add the intersection itself as a synthetic promotion record
                promotions.append(
                    {
                        "promotion_id": self._hash(f"prom:{inter.intersection_id}"),
                        "property_path": inter.property_path,
                        "from_state": EpistemicState.OBSERVED,
                        "to_state": EpistemicState.INFERRED,
                        "min_authority": replay_rule.min_authority_weight,
                        "achieved_authority": inter.total_authority_sum,
                        "rule": "OBSERVED → INFERRED via authority_threshold",
                    }
                )

            # REPLAY_CONFIRMED requires all-agreeing replay
            if inter.consensus_replay_confirmed and inter.total_authority_sum >= 0.8:
                promotions.append(
                    {
                        "promotion_id": self._hash(f"prom:replay:{inter.intersection_id}"),
                        "property_path": inter.property_path,
                        "from_state": EpistemicState.INFERRED,
                        "to_state": EpistemicState.REPLAY_CONFIRMED,
                        "min_authority": 0.8,
                        "achieved_authority": inter.total_authority_sum,
                        "rule": "INFERRED → REPLAY_CONFIRMED via consensus",
                    }
                )

        # Conflicts are NEVER promoted. They stay CONTESTED or REJECTED.
        for cs in conflict_sets:
            promotions.append(
                {
                    "promotion_id": self._hash(f"prom:reject:{cs.conflict_id}"),
                    "property_path": cs.property_path,
                    "from_state": cs.epistemic_state,
                    "to_state": EpistemicState.CONTESTED,
                    "min_authority": 0.0,
                    "achieved_authority": 0.0,
                    "rule": "CONFLICT → CONTESTED (no promotion allowed)",
                }
            )

        return promotions

    # ──────────────────────────────
    #  Entropy Computation
    # ──────────────────────────────

    @staticmethod
    def _compute_claim_entropy(claims: List[SemanticClaim]) -> float:
        """Shannon entropy over the distribution of semantic types across property paths.

        Higher entropy = more ambiguity.
        Monotonically decreasing during quorum = ambiguity reduction.
        """
        if not claims:
            return 0.0
        type_distribution: Dict[str, int] = defaultdict(int)
        for c in claims:
            type_distribution[c.semantic_type] += 1
        total = len(claims)
        entropy = 0.0
        for count in type_distribution.values():
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)
        return round(entropy, 6)

    # ──────────────────────────────
    #  Helpers
    # ──────────────────────────────

    @staticmethod
    def _compute_authority(source_state: str, field: Optional[SemanticField]) -> float:
        """Constitutional authority weight — maps epistemic state to evidence hierarchy.

        Hierarchy (highest → lowest):
        REPLAY_CONFIRMED(1.0) > PROVENANCE_COMPLETE(0.8) > MULTI_TRACE(0.6)
        > SINGLE_TRACE_OBSERVED(0.4) > LLM_INFERRED(0.2)
        """
        mapping = {
            EpistemicState.REPLAY_CONFIRMED: 1.0,
            EpistemicState.VERIFIED: 0.9,
            EpistemicState.INFERRED: 0.8,  # pipeline-inferred, provenance-validated
            EpistemicState.OBSERVED: 0.4,
            EpistemicState.CONTESTED: 0.1,
            EpistemicState.REJECTED: 0.0,
        }
        base = mapping.get(source_state, 0.2)
        # Confidence floor undermines authority
        if field and field.confidence < 0.5:
            base *= 0.5
        return round(base, 4)

    @staticmethod
    def _hash(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:16]

    @staticmethod
    def _collect_post_quorum_claims(
        intersections: List[SemanticIntersection],
        conflict_sets: List[SemanticConflictSet],
        rejected: List[SemanticClaim],
    ) -> List[SemanticClaim]:
        """Collect representative claims for post-quorum entropy measurement.

        For entropy, we compare the ambiguity of the claim population.
        Post-quorum: only intersections represent resolved claims.
        Conflicts and rejected are removed from the resolved set.
        """
        # Build a simplified claim list from intersections
        post: List[SemanticClaim] = []
        for inter in intersections:
            post.append(
                SemanticClaim(
                    claim_id=inter.intersection_id,
                    property_path=inter.property_path,
                    semantic_type=inter.intersected_type,
                    confidence_score=inter.intersected_confidence,
                    artifact_id="synthetic",
                    trace_id=inter.intersection_id,
                    worker_id="semantic_quorum",
                    source_epistemic_state=EpistemicState.INFERRED,
                    replay_confirmed=inter.consensus_replay_confirmed,
                    authority_weight=inter.total_authority_sum,
                )
            )
        # Add rejected (they contribute to preserved ambiguity as negative evidence)
        for r in rejected:
            post.append(r)
        # Add contested conflicts (they represent unresolved ambiguity)
        for cs in conflict_sets:
            post.append(
                SemanticClaim(
                    claim_id=cs.conflict_id,
                    property_path=cs.property_path,
                    semantic_type="CONFLICTED",
                    confidence_score=cs.max_confidence,
                    artifact_id="synthetic",
                    trace_id=cs.conflict_id,
                    worker_id="semantic_quorum",
                    source_epistemic_state=EpistemicState.CONTESTED,
                    replay_confirmed=False,
                    authority_weight=0.0,
                )
            )
        return post
