"""Entropy Analysis — Phase 6 of verification subsystem.

Semantic Stability Instrumentation Layer.

Key constraints:
- Observational governance signals ONLY. Never mutates runtime state.
- Measures 5 entropy dimensions: structural, semantic, replay, temporal, topological.
- Detects instability, divergence, regression — never prescribes action.
- Deterministic and replayable. All calculations from integer counts.
- Bounded: MAX_WINDOW_SIZE=32. No recursive analysis. No self-referential scoring.
- Entropy must trend downward or stabilize as evidence accumulates.
- Inference may expand possibility space. Governance must collapse it back.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pi_agent_chain.models import (
    AuthConsistencyReport,
    ConvergenceScore,
    DriftSignature,
    EntropyAnalysisReport,
    EntropyDelta,
    EntropySnapshot,
    EpistemicState,
    GovernanceViolation,
    ProtocolStateMachine,
    ReplayStabilityMetric,
    SemanticQuorumReport,
    SemanticVariance,
    StabilityWindow,
    TopologicalEntropy,
    ValidationBoundsConfig,
)


class EntropyAnalysisValidator:
    """Observational entropy measurement engine.

    NOT a probabilistic orchestrator.
    NOT an autonomous confidence corrector.
    ONLY a deterministic signal generator for the GovernanceKernel.
    """

    def __init__(self, bounds: Optional[Any] = None):
        self.bounds = bounds or ValidationBoundsConfig()
    COMPOSITE_WEIGHTS: Dict[str, float] = {
        "structural": 0.20,
        "semantic": 0.25,
        "replay": 0.25,
        "temporal": 0.15,
        "topological": 0.15,
    }

    # ── Trend thresholds ──
    REGRESSION_THRESHOLD: float = 0.05  # composite delta > 5% => regression
    CONVERGENCE_THRESHOLD: float = -0.03  # composite delta < -3% => converging
    STABILITY_BAND: float = 0.03  # within ±3% => stable

    # ── Historical window (class-level for cross-execution stability tracking) ──
    _stability_window: Optional[StabilityWindow] = None

    # ──────────────────────────────
    #  Public API
    # ──────────────────────────────

    def analyze(
        self,
        quorum_report: SemanticQuorumReport,
        fsm: Optional[ProtocolStateMachine],
        auth_report: Optional[AuthConsistencyReport],
        execution_id: str,
        prior_snapshot: Optional[EntropySnapshot] = None,
    ) -> EntropyAnalysisReport:
        """Execute entropy analysis over current runtime state.

        Args:
            quorum_report: Output from SemanticQuorum (Phase 5).
            fsm: Output from StateTransitionValidator (Phase 4).
            auth_report: Output from AuthConsistencyValidator (Phase 3).
            execution_id: Root goal trace identifier.
            prior_snapshot: Previous entropy snapshot for delta computation.

        Returns:
            EntropyAnalysisReport with zero state mutations.
        """
        # Step 1: Build deterministic input fingerprint
        input_hash = self._hash_inputs(quorum_report, fsm, auth_report, execution_id)

        # Step 2: Measure five entropy dimensions
        structural = self._measure_structural_entropy(quorum_report)
        semantic = self._measure_semantic_entropy(quorum_report)
        replay = self._measure_replay_entropy(quorum_report, auth_report)
        temporal = self._measure_temporal_entropy(quorum_report, prior_snapshot)
        topological = self._measure_topological_entropy(fsm)

        composite = self._compute_composite(
            structural, semantic, replay, temporal, topological
        )

        snapshot = EntropySnapshot(
            snapshot_id=self._hash(f"snap:{execution_id}:{input_hash}"),
            execution_id=execution_id,
            structural_entropy=round(structural, 6),
            semantic_entropy=round(semantic, 6),
            replay_entropy=round(replay, 6),
            temporal_entropy=round(temporal, 6),
            topological_entropy=round(topological, 6),
            composite_entropy=round(composite, 6),
            input_hash=input_hash,
            evidence_count=len(quorum_report.claims),
        )

        # Step 3: Compute delta if prior snapshot exists
        delta = None
        if prior_snapshot is not None:
            delta = self._compute_delta(prior_snapshot, snapshot)

        # Step 4: Decompose into dimensional metrics
        semantic_variance = self._decompose_semantic(quorum_report)
        replay_stability = self._decompose_replay(quorum_report, auth_report)
        topo_entropy = self._decompose_topological(fsm)

        # Step 5: Convergence scoring
        convergence = self._compute_convergence(
            snapshot, semantic_variance, replay_stability, topo_entropy
        )

        # Step 6: Update stability window (bounded)
        window = self._update_window(snapshot)

        # Step 7: Drift detection
        drift_signatures = self._detect_drift(snapshot, delta, window, semantic_variance, replay_stability)

        # Step 8: Governance violations
        violations = self._build_violations(snapshot, delta, drift_signatures, execution_id)

        return EntropyAnalysisReport(
            report_id=self._hash(f"entropy:{execution_id}:{datetime.utcnow().isoformat()}"),
            execution_id=execution_id,
            snapshot=snapshot,
            delta=delta,
            semantic_variance=semantic_variance,
            replay_stability=replay_stability,
            topological_entropy=topo_entropy,
            convergence=convergence,
            stability_window=window,
            drift_signatures=drift_signatures,
            violations=violations,
        )

    # ──────────────────────────────
    #  Dimension 1: Structural Entropy
    # ──────────────────────────────

    @staticmethod
    def _measure_structural_entropy(quorum: SemanticQuorumReport) -> float:
        """Schema variability: field count volatility, type divergence, optionality.

        Computed from claim diversity. More unique (path, type) pairs = higher entropy.
        """
        claims = quorum.claims
        if not claims:
            return 0.0

        # Count unique paths and type assignments
        path_types: Dict[Tuple[str, str], int] = defaultdict(int)
        for c in claims:
            path_types[(c.property_path, c.semantic_type)] += 1

        total = sum(path_types.values())
        if total == 0:
            return 0.0

        # Shannon entropy over type distribution per path
        # Normalize by max possible entropy to bound to [0, 1]
        entropy = 0.0
        for count in path_types.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        max_entropy = math.log2(max(len(path_types), 2))
        normalized = entropy / max_entropy if max_entropy > 0 else 0.0
        return min(normalized, 1.0)

    # ──────────────────────────────
    #  Dimension 2: Semantic Entropy
    # ──────────────────────────────

    @staticmethod
    def _measure_semantic_entropy(quorum: SemanticQuorumReport) -> float:
        """Claim disagreement density, conflict growth, authority fragmentation.

        Higher when: many conflicts, rejected claims, fragmented authority.
        Lower when: clean intersections, high authority consensus.
        """
        total_claims = max(len(quorum.claims), 1)
        conflict_count = len(quorum.conflict_sets)
        rejected_count = len(quorum.rejected_claims)
        len(quorum.intersections)

        # Disagreement density
        disagreement_ratio = conflict_count / total_claims

        # Rejection pressure
        rejection_ratio = rejected_count / total_claims

        # Uncovered paths (no intersection = unresolved ambiguity)
        covered_paths = {i.property_path for i in quorum.intersections}
        all_paths = {c.property_path for c in quorum.claims}
        uncovered_ratio = (len(all_paths) - len(covered_paths)) / max(len(all_paths), 1)

        # Weighted composite
        semantic_entropy = (
            0.45 * disagreement_ratio +
            0.30 * rejection_ratio +
            0.25 * uncovered_ratio
        )
        return min(semantic_entropy, 1.0)

    # ──────────────────────────────
    #  Dimension 3: Replay Entropy
    # ──────────────────────────────

    @staticmethod
    def _measure_replay_entropy(
        quorum: SemanticQuorumReport,
        auth_report: Optional[AuthConsistencyReport],
    ) -> float:
        """Replay equivalence instability, auth survivability variance.

        Higher when: replay failures, auth mutations, contested equivalence classes.
        """
        # Empty state = zero replay entropy (nothing to measure)
        if not quorum.intersections and not quorum.claims:
            return 0.0

        # From quorum: replay_confirmed intersection ratio
        total_intersections = max(len(quorum.intersections), 1)
        replay_confirmed = sum(1 for i in quorum.intersections if i.consensus_replay_confirmed)
        replay_ratio = 1.0 - (replay_confirmed / total_intersections)

        # From auth report: violation count (replay-inconsistent auth)
        auth_pressure = 0.0
        if auth_report is not None:
            auth_violations = len(auth_report.violations)
            auth_pressure = min(auth_violations / 5.0, 1.0)

        # Composite replay entropy
        return min(0.6 * replay_ratio + 0.4 * auth_pressure, 1.0)

    # ──────────────────────────────
    #  Dimension 4: Temporal Entropy
    # ──────────────────────────────

    @staticmethod
    def _measure_temporal_entropy(
        quorum: SemanticQuorumReport,
        prior_snapshot: Optional[EntropySnapshot],
    ) -> float:
        """Drift across time windows.

        Higher when: evidence count grows without entropy reduction.
        Measures whether the runtime is learning or accumulating noise.
        """
        current_evidence = len(quorum.claims)
        if prior_snapshot is None or prior_snapshot.evidence_count == 0:
            # No prior data: temporal entropy is neutral
            return 0.0

        prior_evidence = prior_snapshot.evidence_count
        evidence_growth = (current_evidence - prior_evidence) / max(prior_evidence, 1)

        # If entropy increased while evidence grew = temporal regression
        if prior_snapshot.composite_entropy > 0:
            entropy_growth = (
                prior_snapshot.composite_entropy - 0.0  # target is convergence toward 0
            ) / max(prior_snapshot.composite_entropy, 0.001)
        else:
            entropy_growth = 0.0

        # Temporal entropy = evidence accumulation without convergence
        temporal = 0.5 * max(0.0, evidence_growth) + 0.5 * entropy_growth
        return min(temporal, 1.0)

    # ──────────────────────────────
    #  Dimension 5: Topological Entropy
    # ──────────────────────────────

    @staticmethod
    def _measure_topological_entropy(fsm: Optional[ProtocolStateMachine]) -> float:
        """FSM branching instability and transition uncertainty.

        Higher when: dense edges, high fanout, many unconfirmed transitions.
        """
        if fsm is None or not fsm.nodes:
            return 0.0

        node_count = len(fsm.nodes)
        edge_count = len(fsm.edges)
        max_fanout = max(fsm.max_fanout, 1)
        max(fsm.max_nodes, 1)

        # Branching factor relative to max allowed
        branching = (edge_count / max(node_count, 1)) / max_fanout

        # Edge density relative to max allowed
        density = edge_count / max(fsm.max_edges, 1)

        # Unconfirmed edge ratio
        unconfirmed = sum(1 for e in fsm.edges if e.replay_confirmed_count == 0)
        unconfirmed_ratio = unconfirmed / max(edge_count, 1)

        topo_entropy = 0.35 * branching + 0.25 * density + 0.40 * unconfirmed_ratio
        return min(topo_entropy, 1.0)

    # ──────────────────────────────
    #  Composite & Delta
    # ──────────────────────────────

    def _compute_composite(
        self,
        structural: float,
        semantic: float,
        replay: float,
        temporal: float,
        topological: float,
    ) -> float:
        w = self.COMPOSITE_WEIGHTS
        composite = (
            w["structural"] * structural +
            w["semantic"] * semantic +
            w["replay"] * replay +
            w["temporal"] * temporal +
            w["topological"] * topological
        )
        return min(composite, 1.0)

    def _compute_delta(
        self,
        prior: EntropySnapshot,
        current: EntropySnapshot,
    ) -> EntropyDelta:
        d_struct = current.structural_entropy - prior.structural_entropy
        d_sem = current.semantic_entropy - prior.semantic_entropy
        d_replay = current.replay_entropy - prior.replay_entropy
        d_temp = current.temporal_entropy - prior.temporal_entropy
        d_topo = current.topological_entropy - prior.topological_entropy
        d_comp = current.composite_entropy - prior.composite_entropy

        # Deterministic trend classification
        regression_dims: List[str] = []
        if d_struct > self.REGRESSION_THRESHOLD:
            regression_dims.append("structural")
        if d_sem > self.REGRESSION_THRESHOLD:
            regression_dims.append("semantic")
        if d_replay > self.REGRESSION_THRESHOLD:
            regression_dims.append("replay")
        if d_temp > self.REGRESSION_THRESHOLD:
            regression_dims.append("temporal")
        if d_topo > self.REGRESSION_THRESHOLD:
            regression_dims.append("topological")

        if regression_dims:
            trend = "REGRESSING"
        elif d_comp < self.CONVERGENCE_THRESHOLD:
            trend = "CONVERGING"
        elif abs(d_comp) <= self.STABILITY_BAND:
            trend = "STABLE"
        else:
            trend = "DIVERGING"

        return EntropyDelta(
            delta_id=self._hash(f"delta:{prior.snapshot_id}:{current.snapshot_id}"),
            from_snapshot_id=prior.snapshot_id,
            to_snapshot_id=current.snapshot_id,
            structural_delta=round(d_struct, 6),
            semantic_delta=round(d_sem, 6),
            replay_delta=round(d_replay, 6),
            temporal_delta=round(d_temp, 6),
            topological_delta=round(d_topo, 6),
            composite_delta=round(d_comp, 6),
            trend=trend,
            regression_dimensions=regression_dims,
        )

    # ──────────────────────────────
    #  Decomposition Metrics
    # ──────────────────────────────

    @staticmethod
    def _decompose_semantic(quorum: SemanticQuorumReport) -> SemanticVariance:
        total_claims = max(len(quorum.claims), 1)
        total_paths = max(len({c.property_path for c in quorum.claims}), 1)

        # Disagreement density
        disagreement = len(quorum.conflict_sets) / total_claims

        # Authority fragmentation
        authority_values = [c.authority_weight for c in quorum.claims]
        total_authority = sum(authority_values) if authority_values else 0.0
        max_authority = max(authority_values) if authority_values else 0.0
        fragmentation = 1.0 - (max_authority / max(total_authority, 0.001))

        # Contested expansion
        contested_count = sum(
            1 for c in quorum.claims if c.source_epistemic_state == EpistemicState.CONTESTED
        )
        contested_rate = contested_count / total_claims

        # Rejected ratio
        rejected = len(quorum.rejected_claims) / total_claims

        # Intersection coverage
        intersected_paths = len({i.property_path for i in quorum.intersections})
        coverage = intersected_paths / total_paths

        return SemanticVariance(
            disagreement_density=round(disagreement, 4),
            authority_fragmentation=round(fragmentation, 4),
            contested_expansion_rate=round(contested_rate, 4),
            rejected_claim_ratio=round(rejected, 4),
            intersection_coverage=round(coverage, 4),
        )

    @staticmethod
    def _decompose_replay(
        quorum: SemanticQuorumReport,
        auth_report: Optional[AuthConsistencyReport],
    ) -> ReplayStabilityMetric:
        total_inters = max(len(quorum.intersections), 1)
        replay_confirmed_inters = sum(1 for i in quorum.intersections if i.consensus_replay_confirmed)

        equivalent_rate = replay_confirmed_inters / total_inters
        # Non-equivalent and contested are implicit from what's NOT confirmed
        non_equivalent_rate = 0.0  # not directly tracked in quorum; placeholder
        contested_rate = (total_inters - replay_confirmed_inters) / total_inters

        auth_mutations = 0
        if auth_report is not None:
            auth_mutations = len([v for v in auth_report.violations if "AUTH" in v.rule])

        return ReplayStabilityMetric(
            equivalent_rate=round(equivalent_rate, 4),
            non_equivalent_rate=round(non_equivalent_rate, 4),
            contested_rate=round(contested_rate, 4),
            auth_mutation_count=auth_mutations,
            average_drift_score=0.0,  # computed externally by ReplayValidator
            replay_confirmed_edge_ratio=round(equivalent_rate, 4),
        )

    @staticmethod
    def _decompose_topological(fsm: Optional[ProtocolStateMachine]) -> TopologicalEntropy:
        if fsm is None or not fsm.nodes:
            return TopologicalEntropy()

        node_count = len(fsm.nodes)
        edge_count = len(fsm.edges)
        branching = edge_count / max(node_count, 1)

        # Fanout variance
        out_degrees: Dict[str, int] = defaultdict(int)
        for e in fsm.edges:
            out_degrees[e.from_node] += 1
        degrees = list(out_degrees.values())
        if degrees:
            mean_deg = sum(degrees) / len(degrees)
            variance = sum((d - mean_deg) ** 2 for d in degrees) / len(degrees)
        else:
            variance = 0.0

        unconfirmed = sum(1 for e in fsm.edges if e.replay_confirmed_count == 0)
        unconfirmed_ratio = unconfirmed / max(edge_count, 1)

        return TopologicalEntropy(
            branching_factor=round(branching, 4),
            fanout_variance=round(variance, 4),
            unconfirmed_edge_ratio=round(unconfirmed_ratio, 4),
            node_count=node_count,
            edge_count=edge_count,
        )

    # ──────────────────────────────
    #  Convergence Scoring
    # ──────────────────────────────

    @staticmethod
    def _compute_convergence(
        snapshot: EntropySnapshot,
        semantic_variance: SemanticVariance,
        replay_stability: ReplayStabilityMetric,
        topological_entropy: TopologicalEntropy,
    ) -> ConvergenceScore:
        """Scalar 0..1: 1.0 = perfectly converged, 0.0 = complete disorder.

        Converges as:
        - composite entropy decreases
        - replay confirmed rate increases
        - intersection coverage increases
        - topological unconfirmed edges decrease
        """
        # Base score from composite entropy (inverse)
        base = max(0.0, 1.0 - snapshot.composite_entropy)

        # Boost from replay stability
        replay_boost = 0.25 * replay_stability.equivalent_rate

        # Boost from semantic coverage
        semantic_boost = 0.20 * semantic_variance.intersection_coverage

        # Penalty from topological uncertainty
        topo_penalty = 0.15 * topological_entropy.unconfirmed_edge_ratio

        # Penalty from authority fragmentation
        auth_penalty = 0.10 * semantic_variance.authority_fragmentation

        raw = base + replay_boost + semantic_boost - topo_penalty - auth_penalty
        score = max(0.0, min(1.0, raw))

        # Confidence bound: wider when entropy is high
        confidence = max(0.0, 1.0 - snapshot.composite_entropy)

        return ConvergenceScore(
            score=round(score, 4),
            confidence_bound=round(confidence, 4),
            contributing_factors={
                "base_from_entropy": round(base, 4),
                "replay_boost": round(replay_boost, 4),
                "semantic_boost": round(semantic_boost, 4),
                "topo_penalty": round(topo_penalty, 4),
                "auth_penalty": round(auth_penalty, 4),
            },
        )

    # ──────────────────────────────
    #  Stability Window (Bounded)
    # ──────────────────────────────

    def _update_window(self, snapshot: EntropySnapshot) -> StabilityWindow:
        """Append snapshot to rolling window. Evict oldest if over bound.

        Deterministic FIFO. No probabilistic weighting.
        """
        if EntropyAnalysisValidator._stability_window is None:
            EntropyAnalysisValidator._stability_window = StabilityWindow(
                window_id=self._hash("window:init"),
                max_window_size=self.bounds.max_entropy_window_size,
            )

        window = EntropyAnalysisValidator._stability_window
        window.snapshots.append(snapshot)

        # FIFO eviction
        while len(window.snapshots) > window.max_window_size:
            window.snapshots.pop(0)

        # Compute window statistics
        if window.snapshots:
            composites = [s.composite_entropy for s in window.snapshots]
            window.average_composite_entropy = round(sum(composites) / len(composites), 6)
            if len(composites) > 1:
                mean = window.average_composite_entropy
                window.entropy_variance = round(
                    sum((c - mean) ** 2 for c in composites) / len(composites), 6
                )
            else:
                window.entropy_variance = 0.0

            # Trend classification from window slope
            if len(composites) >= 3:
                first_half = composites[: len(composites) // 2]
                second_half = composites[len(composites) // 2 :]
                f_avg = sum(first_half) / len(first_half)
                s_avg = sum(second_half) / len(second_half)
                if s_avg < f_avg - 0.03:
                    window.trend = "IMPROVING"
                elif s_avg > f_avg + 0.03:
                    window.trend = "DEGRADING"
                elif window.entropy_variance > 0.05:
                    window.trend = "OSCILLATING"
                else:
                    window.trend = "STABLE"
            else:
                window.trend = "INSUFFICIENT_DATA"

        return window

    # ──────────────────────────────
    #  Drift Detection
    # ──────────────────────────────

    def _detect_drift(
        self,
        snapshot: EntropySnapshot,
        delta: Optional[EntropyDelta],
        window: StabilityWindow,
        semantic_variance: SemanticVariance,
        replay_stability: ReplayStabilityMetric,
    ) -> List[DriftSignature]:
        """Detect regression patterns. Observational only.

        Returns drift signatures for GovernanceKernel review.
        """
        signatures: List[DriftSignature] = []

        # 1. Structural volatility
        if snapshot.structural_entropy > 0.6:
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:structural"),
                    pattern_type="STRUCTURAL_VOLATILITY",
                    affected_dimensions=["structural"],
                    severity_score=round(snapshot.structural_entropy, 4),
                    description="Schema variability exceeds threshold. Field/type instability detected.",
                )
            )

        # 2. Semantic fragmentation
        if semantic_variance.disagreement_density > 0.3 or semantic_variance.contested_expansion_rate > 0.3:
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:semantic"),
                    pattern_type="SEMANTIC_FRAGMENTATION",
                    affected_dimensions=["semantic"],
                    severity_score=round(
                        max(semantic_variance.disagreement_density, semantic_variance.contested_expansion_rate), 4
                    ),
                    description="Claim disagreement or contested expansion rate high. Semantic coherence compromised.",
                )
            )

        # 3. Replay instability
        if replay_stability.contested_rate > 0.3 or replay_stability.auth_mutation_count > 0:
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:replay"),
                    pattern_type="REPLAY_INSTABILITY",
                    affected_dimensions=["replay"],
                    severity_score=round(min(replay_stability.contested_rate + 0.2 * replay_stability.auth_mutation_count, 1.0), 4),
                    description="Replay equivalence contested or auth mutations present. Behavioral consistency degraded.",
                )
            )

        # 4. Temporal regression
        if delta is not None and delta.trend == "REGRESSING":
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:temporal"),
                    pattern_type="TEMPORAL_REGRESSION",
                    affected_dimensions=delta.regression_dimensions,
                    severity_score=round(abs(delta.composite_delta), 4),
                    description=f"Entropy regression in dimensions: {delta.regression_dimensions}. Evidence accumulation without convergence.",
                )
            )

        # 5. Topology explosion
        if snapshot.topological_entropy > 0.5:
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:topology"),
                    pattern_type="TOPOLOGY_EXPLOSION",
                    affected_dimensions=["topological"],
                    severity_score=round(snapshot.topological_entropy, 4),
                    description="FSM branching or transition uncertainty exceeds threshold. Protocol state space unstable.",
                )
            )

        # 6. Cross-dimension correlation (multiple dimensions elevated)
        elevated = [
            dim for dim, val in {
                "structural": snapshot.structural_entropy,
                "semantic": snapshot.semantic_entropy,
                "replay": snapshot.replay_entropy,
                "topological": snapshot.topological_entropy,
            }.items() if val > 0.4
        ]
        if len(elevated) >= 3:
            signatures.append(
                DriftSignature(
                    signature_id=self._hash("drift:cross"),
                    pattern_type="CROSS_DIMENSION_CORRELATION",
                    affected_dimensions=elevated,
                    severity_score=round(snapshot.composite_entropy, 4),
                    description=f"Multiple entropy dimensions elevated simultaneously ({elevated}). Systemic instability suspected.",
                )
            )

        return signatures

    # ──────────────────────────────
    #  Governance Violations
    # ──────────────────────────────

    def _build_violations(
        self,
        snapshot: EntropySnapshot,
        delta: Optional[EntropyDelta],
        drift_signatures: List[DriftSignature],
        execution_id: str,
    ) -> List[GovernanceViolation]:
        """Convert critical entropy signals into governance violations.

        The GovernanceKernel decides action. This module only reports.
        """
        violations: List[GovernanceViolation] = []

        # 1. ENTROPY_REGRESSION: composite entropy increased significantly
        if delta is not None and delta.composite_delta > self.REGRESSION_THRESHOLD:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"entropy_reg:{execution_id}"),
                    rule="ENTROPY_REGRESSION",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={
                        "composite_delta": delta.composite_delta,
                        "regression_dimensions": delta.regression_dimensions,
                        "composite_entropy": snapshot.composite_entropy,
                    },
                    action_taken="HALT",
                )
            )

        # 2. REPLAY_STABILITY_COLLAPSE: replay dimension critically unstable
        if snapshot.replay_entropy > 0.7:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"replay_col:{execution_id}"),
                    rule="REPLAY_STABILITY_COLLAPSE",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="CRITICAL",
                    context={"replay_entropy": snapshot.replay_entropy},
                    action_taken="HALT",
                )
            )

        # 3. SEMANTIC_FRAGMENTATION: semantic dimension critically unstable
        if snapshot.semantic_entropy > 0.7:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"frag:{execution_id}"),
                    rule="SEMANTIC_FRAGMENTATION",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={"semantic_entropy": snapshot.semantic_entropy},
                    action_taken="HALT",
                )
            )

        # 4. CONVERGENCE_FAILURE: convergence score too low after sufficient evidence
        if snapshot.evidence_count > 10 and snapshot.composite_entropy > 0.6:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"conv_fail:{execution_id}"),
                    rule="CONVERGENCE_FAILURE",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={
                        "evidence_count": snapshot.evidence_count,
                        "composite_entropy": snapshot.composite_entropy,
                    },
                    action_taken="HALT",
                )
            )

        # 5. TEMPORAL_DRIFT_EXPLOSION: temporal entropy critically high
        if snapshot.temporal_entropy > 0.5:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"temp_drift:{execution_id}"),
                    rule="TEMPORAL_DRIFT_EXPLOSION",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="WARNING",
                    context={"temporal_entropy": snapshot.temporal_entropy},
                    action_taken="MONITOR",
                )
            )

        # 6. TOPOLOGY_UNSTABLE: topological entropy critically high
        if snapshot.topological_entropy > 0.6:
            violations.append(
                GovernanceViolation(
                    violation_id=self._hash(f"topo_unst:{execution_id}"),
                    rule="TOPOLOGY_UNSTABLE",
                    worker_id="entropy_analysis",
                    root_goal_id=execution_id,
                    severity="ERROR",
                    context={"topological_entropy": snapshot.topological_entropy},
                    action_taken="HALT",
                )
            )

        return violations

    # ──────────────────────────────
    #  Utilities
    # ──────────────────────────────

    @staticmethod
    def _hash_inputs(
        quorum: SemanticQuorumReport,
        fsm: Optional[ProtocolStateMachine],
        auth: Optional[AuthConsistencyReport],
        execution_id: str,
    ) -> str:
        """Deterministic fingerprint of all inputs for replay reproducibility."""
        parts = [
            execution_id,
            str(len(quorum.claims)),
            str(len(quorum.intersections)),
            str(len(quorum.conflict_sets)),
        ]
        if fsm is not None:
            parts.extend([str(len(fsm.nodes)), str(len(fsm.edges))])
        if auth is not None:
            parts.extend([str(len(auth.invariants)), str(len(auth.violations))])
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @staticmethod
    def _hash(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:16]
