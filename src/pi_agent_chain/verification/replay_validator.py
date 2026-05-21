"""Replay Validator — Phase 2 of verification subsystem.

Deterministic Semantic Replay Governance.

Key constraint: operates on Canonical Semantic IR, never raw bytes.
Observational only. Returns GovernanceViolations. Never mutates state.

Canonicalization rules (deterministic noise removal):
- strip volatile timestamps from frozen_at
- ignore provenance list ordering
- ignore example_value content (not structural)
- retain: endpoint_template, method, field paths, inferred_types, confidence scores
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Set, Tuple

from pi_agent_chain.models import (
    EpistemicState,
    EquivalenceClass,
    GovernanceViolation,
    MutationAwareEquivalence,
    MutationClass,
    SemanticDiff,
    SemanticField,
    SemanticIRTrace,
    StatefulReplayClassification,
)


class ReplayValidator:
    """Compare original and replay SemanticIRTraces.

    All outputs are observational. The runtime decides whether to act.
    """

    # Thresholds for equivalence classification
    STRICT_THRESHOLD = 0.0    # zero structural or semantic drift
    SEMANTIC_THRESHOLD = 0.10 # up to 10% structural drift, core semantics intact
    PARTIAL_THRESHOLD = 0.35  # up to 35% drift, endpoint/method stable
    MAX_DRIFT = 1.0

    def __init__(self, schema_version: str = "1.0.0"):
        self.schema_version = schema_version

    # ──────────────────────────────
    #  Public API
    # ──────────────────────────────

    def compare(
        self,
        original: SemanticIRTrace,
        replay: SemanticIRTrace,
        execution_id: str = "",
    ) -> Tuple[SemanticDiff, List[GovernanceViolation]]:
        """Compute semantic diff and governance violations between two traces.

        Returns:
            SemanticDiff — structured comparison result
            List[GovernanceViolation] — detected governance breaches
        """
        # Canonicalize both traces before comparison
        orig_c = self._canonicalize(original)
        replay_c = self._canonicalize(replay)

        diff = self._compute_diff(orig_c, replay_c)
        violations = self._evaluate_governance(diff, execution_id)

        return diff, violations

    # ──────────────────────────────
    #  Mutation-Aware Replay (Gap 2)
    # ──────────────────────────────

    def compare_with_mutation_context(
        self,
        original: SemanticIRTrace,
        replay: SemanticIRTrace,
        original_status: int = 200,
        replay_status: int = 200,
        execution_id: str = "",
    ) -> MutationAwareEquivalence:
        """Compare traces with mutation-aware classification.

        Distinguishes expected stateful behavior from genuine structural divergence.
        Auth drift and mutation drift remain independent dimensions.

        Key rule: stateful mutations (POST /checkout) that diverge structurally
        from a replay are NOT automatically NON_EQUIVALENT. The comparison
        checks whether the response SCHEMA still matches (semantic survivability)
        and whether the status code is consistent with mutation behavior.

        Observational only. Never mutates state.
        """
        # Step 1: Standard canonicalization and diff
        orig_c = self._canonicalize(original)
        replay_c = self._canonicalize(replay)
        diff = self._compute_diff(orig_c, replay_c)

        # Step 2: Mutation class inference (deterministic, not learned)
        mutation_class = self._infer_mutation_class(
            original.method,
            original_status,
            replay_status,
            diff,
        )

        # Step 3: Statefulness classification
        stateful_class = self._infer_stateful_class(
            mutation_class,
            original_status,
            replay_status,
            diff,
        )

        # Step 4: Structure-match detection (schema survivability, not byte equality)
        structure_matches = self._check_structure_survivability(diff)

        # Step 5: Status-code expectation check
        status_code_matches = self._check_status_expectation(
            mutation_class,
            original_status,
            replay_status,
        )

        # Step 6: Semantic field agreement (path/type intersection)
        semantic_agreement = self._compute_semantic_agreement(diff)

        # Step 7: Determine if this is expected stateful variation
        is_expected = self._is_expected_stateful_variation(
            mutation_class,
            stateful_class,
            structure_matches,
            status_code_matches,
            diff,
        )

        # Step 8: Auth drift is tracked independently via diff.auth_mutations
        # It does NOT affect mutation classification.

        # Step 9: Equivalence classification respecting mutation context
        equivalence_class = self._classify_mutation_aware_equivalence(
            diff,
            mutation_class,
            is_expected,
            structure_matches,
        )

        # Step 10: Build violations (auth drift is still a violation)
        violations: List[GovernanceViolation] = []
        if diff.auth_mutations:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"auth_mutation:{execution_id}"),
                    rule="REPLAY_AUTH_MUTATION",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={
                        "auth_mutations": diff.auth_mutations,
                        "drift_score": diff.drift_score,
                        "mutation_class": mutation_class,
                    },
                    action_taken="HALT",
                )
            )

        # REPLAY_UNSAFE endpoints are never replayed; violation signals prohibition
        if mutation_class == MutationClass.REPLAY_UNSAFE:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"replay_unsafe:{execution_id}"),
                    rule="REPLAY_UNSAFE_ENDPOINT",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"method": original.method, "endpoint": original.endpoint_template},
                    action_taken="SKIP_REPLAY",
                )
            )

        # Destructive divergence that is NOT expected is still NON_EQUIVALENT
        if not is_expected and not structure_matches and diff.drift_score > self.PARTIAL_THRESHOLD:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"unexpected_divergence:{execution_id}"),
                    rule="REPLAY_UNEXPECTED_DIVERGENCE",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={
                        "drift_score": diff.drift_score,
                        "structural_delta": diff.structural_delta_score,
                        "mutation_class": mutation_class,
                        "stateful_class": stateful_class,
                    },
                    action_taken="HALT",
                )
            )

        return MutationAwareEquivalence(
            equivalence_class=equivalence_class,
            mutation_class=mutation_class,
            stateful_class=stateful_class,
            is_expected_stateful_variation=is_expected,
            structure_matches=structure_matches,
            status_code_matches=status_code_matches,
            semantic_field_agreement=semantic_agreement,
            description=self._describe_mutation_context(
                mutation_class, stateful_class, is_expected, diff
            ),
            violations=violations,
        )

    def _infer_mutation_class(
        self,
        method: str,
        original_status: int,
        replay_status: int,
        diff: SemanticDiff,
    ) -> str:
        """Infer mutation class from method + status code + diff patterns.

        Deterministic. Observational. NOT learned from naming.

        NOTE: REPLAY_UNSAFE must be set EXTERNALLY by the pipeline.
        This classifier only infers observational classes.
        """
        method = method.upper()

        # NON_DETERMINISTIC: high drift on stable read operations
        # Exclude auth-mutation drift from this classification — auth is independent
        if method in ("GET", "HEAD") and diff.endpoint_stable and diff.method_stable:
            # Compute drift without auth mutations
            auth_mutation_count = len(diff.auth_mutations)
            len(diff.added_fields) + len(diff.removed_fields) + len(diff.type_mutations)
            # Recompute semantic delta excluding auth mutations
            non_auth_semantic = max(0, (len(diff.type_mutations) - auth_mutation_count) * 0.6)
            non_auth_drift = (diff.structural_delta_score * 0.4) + non_auth_semantic
            if non_auth_drift > self.PARTIAL_THRESHOLD:
                return MutationClass.NON_DETERMINISTIC

        # IDEMPOTENT_READ: GET, HEAD, OPTIONS (only if drift is low)
        if method in ("GET", "HEAD", "OPTIONS"):
            return MutationClass.IDEMPOTENT_READ

        # DESTRUCTIVE_MUTATION: DELETE always
        if method == "DELETE":
            return MutationClass.DESTRUCTIVE_MUTATION

        # SIDE_EFFECT_BOUND: POST/PATCH returning 202/204 (async, webhook)
        if method in ("POST", "PATCH") and replay_status in (202, 204):
            return MutationClass.SIDE_EFFECT_BOUND

        # STATEFUL_MUTATION: POST/PUT/PATCH that modify server state
        if method in ("POST", "PUT", "PATCH"):
            # PUT to existing resource = idempotent if no drift and status matches
            if method == "PUT" and original_status in (200, 204):
                if replay_status in (200, 204) and diff.structural_delta_score < self.SEMANTIC_THRESHOLD:
                    return MutationClass.IDEMPOTENT_READ
            return MutationClass.STATEFUL_MUTATION

        return MutationClass.UNKNOWN

    def _infer_stateful_class(
        self,
        mutation_class: str,
        original_status: int,
        replay_status: int,
        diff: SemanticDiff,
    ) -> str:
        """Classify how state affects replay behavior."""
        if mutation_class == MutationClass.IDEMPOTENT_READ:
            if diff.structural_delta_score == 0.0:
                return StatefulReplayClassification.STATELESS
            return StatefulReplayClassification.STATE_DEPENDENT

        if mutation_class == MutationClass.STATEFUL_MUTATION:
            if replay_status == 409 and original_status == 201:
                # Second POST of same checkout = conflict (expected)
                return StatefulReplayClassification.STATE_DEPENDENT
            if replay_status == 200 and original_status == 201:
                # POST that now returns existing resource = state dependent
                return StatefulReplayClassification.STATE_DEPENDENT
            if replay_status in (400, 422) and original_status == 201:
                # Validation failed on replay (e.g., duplicate transaction)
                return StatefulReplayClassification.STATE_DEPENDENT
            return StatefulReplayClassification.SEQUENCE_DEPENDENT

        if mutation_class == MutationClass.DESTRUCTIVE_MUTATION:
            if replay_status == 404 and original_status == 204:
                # DELETE then DELETE again = not found (expected)
                return StatefulReplayClassification.STATE_DEPENDENT
            return StatefulReplayClassification.STATELESS

        if mutation_class == MutationClass.NON_DETERMINISTIC:
            return StatefulReplayClassification.TIME_DEPENDENT

        return StatefulReplayClassification.UNKNOWN

    def _check_structure_survivability(self, diff: SemanticDiff) -> bool:
        """Check if response schema survived mutation (not byte equality).

        True if: endpoint+method stable AND structural delta below threshold
        OR type mutations are only value-level (not path-level).
        """
        if not diff.endpoint_stable or not diff.method_stable:
            return False

        # Structural delta measures path changes; below threshold = schema intact
        if diff.structural_delta_score <= self.SEMANTIC_THRESHOLD:
            return True

        # Even with some structural drift, if type mutations are minor
        if diff.semantic_delta_score <= self.SEMANTIC_THRESHOLD:
            return True

        return False

    def _check_status_expectation(
        self,
        mutation_class: str,
        original_status: int,
        replay_status: int,
    ) -> bool:
        """Check if replay status is consistent with mutation class expectations."""
        if mutation_class == MutationClass.IDEMPOTENT_READ:
            return original_status == replay_status

        if mutation_class == MutationClass.STATEFUL_MUTATION:
            # First call 201, replay 409/200/422 = all acceptable for stateful
            if original_status == 201 and replay_status in (200, 201, 409, 422, 400):
                return True
            if original_status == 200 and replay_status in (200, 204, 409):
                return True
            return False

        if mutation_class == MutationClass.DESTRUCTIVE_MUTATION:
            # First DELETE 204, second DELETE 404 = acceptable
            if original_status == 204 and replay_status in (204, 404, 410):
                return True
            return original_status == replay_status

        if mutation_class == MutationClass.REPLAY_UNSAFE:
            return False  # Never replayed

        return original_status == replay_status

    def _compute_semantic_agreement(self, diff: SemanticDiff) -> float:
        """Compute semantic field agreement ratio (0.0–1.0)."""
        total_fields = len(diff.added_fields) + len(diff.removed_fields) + len(diff.type_mutations)
        if total_fields == 0:
            return 1.0
        # Agreement = fields that did NOT change / total observed fields
        # Approximate using drift score inverse
        return max(0.0, 1.0 - diff.drift_score)

    def _is_expected_stateful_variation(
        self,
        mutation_class: str,
        stateful_class: str,
        structure_matches: bool,
        status_code_matches: bool,
        diff: SemanticDiff,
    ) -> bool:
        """Determine if observed divergence is expected for this mutation class."""
        # REPLAY_UNSAFE: never expected; replay should not have occurred
        if mutation_class == MutationClass.REPLAY_UNSAFE:
            return False

        # IDEMPOTENT_READ: any divergence is unexpected
        if mutation_class == MutationClass.IDEMPOTENT_READ:
            return diff.structural_delta_score == 0.0 and diff.semantic_delta_score == 0.0

        # STATEFUL_MUTATION: divergence is expected if structure survives
        if mutation_class == MutationClass.STATEFUL_MUTATION:
            if stateful_class == StatefulReplayClassification.STATE_DEPENDENT:
                return structure_matches  # Schema intact = expected variation
            if stateful_class == StatefulReplayClassification.SEQUENCE_DEPENDENT:
                return structure_matches and status_code_matches
            return False

        # DESTRUCTIVE_MUTATION: 404 after 204 is expected
        if mutation_class == MutationClass.DESTRUCTIVE_MUTATION:
            return structure_matches or diff.structural_delta_score <= self.SEMANTIC_THRESHOLD

        # NON_DETERMINISTIC: variation is inherent, but only if structure matches
        if mutation_class == MutationClass.NON_DETERMINISTIC:
            return structure_matches

        return False

    def _classify_mutation_aware_equivalence(
        self,
        diff: SemanticDiff,
        mutation_class: str,
        is_expected: bool,
        structure_matches: bool,
    ) -> str:
        """Classify equivalence considering mutation context.

        CRITICAL: Never silently downgrade destructive divergence.
        """
        if mutation_class == MutationClass.REPLAY_UNSAFE:
            return EquivalenceClass.NON_EQUIVALENT

        if not diff.endpoint_stable or not diff.method_stable:
            return EquivalenceClass.NON_EQUIVALENT

        if is_expected:
            # Expected stateful variation → SEMANTIC_EQUIVALENT (schema survives)
            if structure_matches:
                if diff.structural_delta_score == 0.0 and diff.semantic_delta_score == 0.0:
                    return EquivalenceClass.STRICT_EQUIVALENT
                return EquivalenceClass.SEMANTIC_EQUIVALENT
            # Expected but structure broken → PARTIAL_EQUIVALENT
            return EquivalenceClass.PARTIAL_EQUIVALENT

        # Not expected → use standard thresholds
        return self.classify_replay(diff)

    def _describe_mutation_context(
        self,
        mutation_class: str,
        stateful_class: str,
        is_expected: bool,
        diff: SemanticDiff,
    ) -> str:
        """Human-readable description of mutation context."""
        parts = [
            f"mutation={mutation_class}",
            f"stateful={stateful_class}",
            f"expected_variation={is_expected}",
            f"structure_matches={self._check_structure_survivability(diff)}",
            f"drift={diff.drift_score:.3f}",
        ]
        return "; ".join(parts)

    def classify_replay(
        self,
        diff: SemanticDiff,
    ) -> str:
        """Classify replay into an EquivalenceClass based on diff scores.

        Deterministic. Idempotent. Stateless.
        """
        s = diff.structural_delta_score
        m = diff.semantic_delta_score

        if not diff.endpoint_stable or not diff.method_stable:
            return EquivalenceClass.NON_EQUIVALENT

        if s == 0.0 and m == 0.0:
            return EquivalenceClass.STRICT_EQUIVALENT

        if s <= self.SEMANTIC_THRESHOLD and m <= self.SEMANTIC_THRESHOLD:
            return EquivalenceClass.SEMANTIC_EQUIVALENT

        if s <= self.PARTIAL_THRESHOLD and m <= self.PARTIAL_THRESHOLD:
            return EquivalenceClass.PARTIAL_EQUIVALENT

        if s > self.PARTIAL_THRESHOLD or m > self.PARTIAL_THRESHOLD:
            return EquivalenceClass.NON_EQUIVALENT

        return EquivalenceClass.CONTESTED

    # ──────────────────────────────
    #  Canonicalization
    # ──────────────────────────────

    @staticmethod
    def _canonicalize(trace: SemanticIRTrace) -> SemanticIRTrace:
        """Remove volatile / non-semantic fields before comparison.

        Strips:
        - timestamps (frozen_at)
        - example_value (not structural)
        - provenance ordering
        - epistemic_state (may change under governance)
        """
        fields = sorted(
            [
                SemanticField(
                    path=f.path,
                    inferred_type=f.inferred_type,
                    confidence=f.confidence,
                    entropy_score=f.entropy_score,
                )
                for f in trace.fields
            ],
            key=lambda f: f.path,
        )
        return SemanticIRTrace(
            endpoint_template=trace.endpoint_template,
            method=trace.method,
            fields=fields,
            is_frozen=trace.is_frozen,
            epistemic_state=EpistemicState.INFERRED,  # neutral state for comparison
            provenance=[],
            semantic_hash=trace.semantic_hash,
            generated_by=trace.generated_by,
        )

    # ──────────────────────────────
    #  Diff computation
    # ──────────────────────────────

    def _compute_diff(
        self,
        original: SemanticIRTrace,
        replay: SemanticIRTrace,
    ) -> SemanticDiff:
        """Compute structural and semantic deltas."""
        endpoint_stable = original.endpoint_template == replay.endpoint_template
        method_stable = original.method == replay.method

        # Field-level analysis
        orig_fields: Dict[str, SemanticField] = {f.path: f for f in original.fields}
        replay_fields: Dict[str, SemanticField] = {f.path: f for f in replay.fields}

        orig_paths: Set[str] = set(orig_fields.keys())
        replay_paths: Set[str] = set(replay_fields.keys())

        added = list(replay_paths - orig_paths)
        removed = list(orig_paths - replay_paths)
        common = orig_paths & replay_paths

        type_mutations: List[str] = []
        auth_mutations: List[str] = []
        confidence_drift: float = 0.0

        for path in common:
            o = orig_fields[path]
            r = replay_fields[path]
            if o.inferred_type != r.inferred_type:
                type_mutations.append(f"{path}: {o.inferred_type} -> {r.inferred_type}")
            # Auth-related type changes are classified separately
            if o.inferred_type in ("JWT", "Base64", "HexDigest", "UNKNOWN_HEX"):
                if r.inferred_type not in ("JWT", "Base64", "HexDigest", "UNKNOWN_HEX"):
                    auth_mutations.append(f"{path}: auth material lost")
            elif r.inferred_type in ("JWT", "Base64", "HexDigest", "UNKNOWN_HEX"):
                if o.inferred_type not in ("JWT", "Base64", "HexDigest", "UNKNOWN_HEX"):
                    auth_mutations.append(f"{path}: auth material appeared")

            confidence_drift += abs(o.confidence - r.confidence)

        # Structural delta: fraction of field structure that changed
        total_paths = len(orig_paths | replay_paths)
        structural_delta = (
            (len(added) + len(removed)) / total_paths if total_paths > 0 else 0.0
        )

        # Semantic delta: type mutations + auth shifts + confidence drift
        mutation_count = len(type_mutations) + len(auth_mutations)
        semantic_delta = (
            (mutation_count + confidence_drift) / total_paths if total_paths > 0 else 0.0
        )
        semantic_delta = min(semantic_delta, 1.0)

        # Drift score: weighted composite
        drift = (structural_delta * 0.4) + (semantic_delta * 0.6)
        drift = min(drift, 1.0)

        diff = SemanticDiff(
            structural_delta_score=round(structural_delta, 4),
            semantic_delta_score=round(semantic_delta, 4),
            added_fields=added,
            removed_fields=removed,
            type_mutations=type_mutations,
            auth_mutations=auth_mutations,
            endpoint_stable=endpoint_stable,
            method_stable=method_stable,
            replay_equivalence=EquivalenceClass.CONTESTED,  # placeholder; set by classify_replay
            drift_score=round(drift, 4),
            canonicalized=True,
        )
        diff.replay_equivalence = self.classify_replay(diff)
        return diff

    # ──────────────────────────────
    #  Governance evaluation
    # ──────────────────────────────

    def _evaluate_governance(
        self,
        diff: SemanticDiff,
        execution_id: str,
    ) -> List[GovernanceViolation]:
        """Transform diff into governance violations.

        Observational only. The runtime (GovernanceKernel) decides to halt.
        """
        violations: List[GovernanceViolation] = []

        if diff.replay_equivalence == EquivalenceClass.NON_EQUIVALENT:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"non_equiv:{execution_id}"),
                    rule="REPLAY_NON_EQUIVALENT",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={
                        "drift_score": diff.drift_score,
                        "structural_delta": diff.structural_delta_score,
                        "semantic_delta": diff.semantic_delta_score,
                        "endpoint_stable": diff.endpoint_stable,
                        "method_stable": diff.method_stable,
                    },
                    action_taken="HALT",
                )
            )

        if diff.auth_mutations:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"auth_mutation:{execution_id}"),
                    rule="REPLAY_AUTH_MUTATION",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={
                        "auth_mutations": diff.auth_mutations,
                        "drift_score": diff.drift_score,
                    },
                    action_taken="HALT",
                )
            )

        if diff.drift_score > 0.5:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"high_drift:{execution_id}"),
                    rule="REPLAY_HIGH_DRIFT",
                    worker_id="replay_validator",
                    root_goal_id=execution_id,
                    severity="WARNING",
                    context={
                        "drift_score": diff.drift_score,
                        "type_mutations": diff.type_mutations,
                    },
                    action_taken="REVIEW",
                )
            )

        return violations

    @staticmethod
    def _hash(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:16]
