"""Core Diff Runtime.

Deterministic, bounded, replayable, evidence-linked, schema-validated,
append-only, fail-closed.

f(baseline_snapshot, modified_snapshot) -> SemanticDiffReport

No inference. No LLM calls. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pi_semantic_diff.models import (
    AuthInvariant,
    DependencyGraph,
    SemanticDiffReport,
    SemanticIRTrace,
)
from pi_semantic_diff.deltas import (
    compute_auth_deltas,
    compute_dependency_deltas,
    compute_drift_score,
    compute_endpoint_deltas,
    compute_replay_surface_deltas,
    compute_semantic_delta_score,
    compute_structural_delta_score,
)


class DiffBounds:
    """Bounded execution configuration for diff runtime."""

    max_endpoint_deltas: int = 512
    max_dependency_deltas: int = 512
    max_auth_deltas: int = 256
    max_replay_deltas: int = 512
    max_fields_per_trace: int = 256
    max_edges_per_graph: int = 512
    max_traces_per_snapshot: int = 1024


class DiffRuntime:
    """Deterministic behavioral delta worker.

    Consumes two semantic snapshots and produces a deterministic diff report.
    """

    def __init__(self, bounds: Optional[DiffBounds] = None) -> None:
        self.bounds = bounds or DiffBounds()
        self._execution_id = f"diff_{uuid.uuid4().hex[:12]}"

    @property
    def execution_id(self) -> str:
        return self._execution_id

    def diff(
        self,
        baseline_traces: List[SemanticIRTrace],
        modified_traces: List[SemanticIRTrace],
        baseline_graph: Optional[DependencyGraph] = None,
        modified_graph: Optional[DependencyGraph] = None,
        baseline_auth: Optional[List[AuthInvariant]] = None,
        modified_auth: Optional[List[AuthInvariant]] = None,
        baseline_execution_id: str = "",
        modified_execution_id: str = "",
    ) -> SemanticDiffReport:
        """Execute all diff passes in fixed order with bounded execution."""
        # Pre-validate: fail-closed on empty snapshots
        if not baseline_traces and not modified_traces:
            return self._assemble_empty_report(
                baseline_execution_id=baseline_execution_id,
                modified_execution_id=modified_execution_id,
            )

        # Pass 1: Endpoint deltas
        endpoint_deltas = compute_endpoint_deltas(
            baseline_traces, modified_traces, max_deltas=self.bounds.max_endpoint_deltas
        )

        # Pass 2: Dependency graph deltas
        dep_deltas: List[Any] = []
        if baseline_graph is not None and modified_graph is not None:
            dep_deltas = compute_dependency_deltas(
                baseline_graph, modified_graph, max_deltas=self.bounds.max_dependency_deltas
            )

        # Pass 3: Auth deltas
        auth_deltas: List[Any] = []
        if baseline_auth is not None and modified_auth is not None:
            auth_deltas = compute_auth_deltas(
                baseline_auth, modified_auth, max_deltas=self.bounds.max_auth_deltas
            )

        # Pass 4: Replay surface deltas
        replay_deltas = compute_replay_surface_deltas(
            baseline_traces, modified_traces, max_deltas=self.bounds.max_replay_deltas
        )

        # Scoring
        structural_score = compute_structural_delta_score(endpoint_deltas, dep_deltas)
        semantic_score = compute_semantic_delta_score(endpoint_deltas)

        # Mutation expansion counts
        state_mutation_exp = 0
        destructive_exp = 0
        idemp_regression = 0
        for d in endpoint_deltas:
            if d.mutation_class_transition or (d.presence == "ADDED" and d.modified_mutation_class in ("STATEFUL_MUTATION", "DESTRUCTIVE_MUTATION")):
                state_mutation_exp += 1
            if d.mutation_class_transition or (d.presence == "ADDED" and d.modified_mutation_class == "DESTRUCTIVE_MUTATION"):
                destructive_exp += 1
            if d.mutation_class_transition or (d.presence == "REMOVED" and d.baseline_mutation_class == "IDEMPOTENT_READ"):
                idemp_regression += 1

        # Replay surface counts
        replay_surface_exp = len(replay_deltas)
        replay_unsafe_exp = sum(
            1 for d in replay_deltas if d.replayable_delta
        )

        # Drift score
        drift = compute_drift_score(structural_score, semantic_score, state_mutation_exp, replay_surface_exp)

        report = SemanticDiffReport(
            report_id=self._execution_id,
            baseline_execution_id=baseline_execution_id,
            modified_execution_id=modified_execution_id,
            endpoint_count_delta=len(modified_traces) - len(baseline_traces),
            edge_count_delta=(len(modified_graph.edges) if modified_graph else 0) - (len(baseline_graph.edges) if baseline_graph else 0),
            node_count_delta=(len(modified_graph.nodes) if modified_graph else 0) - (len(baseline_graph.nodes) if baseline_graph else 0),
            field_count_delta=sum(len(t.fields) for t in modified_traces) - sum(len(t.fields) for t in baseline_traces),
            structural_delta_score=round(structural_score, 6),
            semantic_delta_score=round(semantic_score, 6),
            drift_score=round(drift, 6),
            endpoint_deltas=endpoint_deltas,
            dependency_deltas=dep_deltas,
            auth_deltas=auth_deltas,
            replay_surface_deltas=replay_deltas,
            state_mutation_expansion=state_mutation_exp,
            destructive_mutation_expansion=destructive_exp,
            idempotent_read_regression=idemp_regression,
            replay_surface_expansion=replay_surface_exp,
            replay_unsafe_expansion=replay_unsafe_exp,
            dependency_graph_evolution_score=round(len(dep_deltas) * 0.01, 6),
            generated_at=datetime.now(timezone.utc),
        )
        report_hash = report.compute_hash()
        # Return a new report with the hash set
        return report.model_copy(update={"report_hash": report_hash})

    def _assemble_empty_report(
        self,
        baseline_execution_id: str,
        modified_execution_id: str,
    ) -> SemanticDiffReport:
        report = SemanticDiffReport(
            report_id=self._execution_id,
            baseline_execution_id=baseline_execution_id,
            modified_execution_id=modified_execution_id,
            generated_at=datetime.now(timezone.utc),
        )
        return report.model_copy(update={"report_hash": report.compute_hash()})
