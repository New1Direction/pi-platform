"""pi-semantic-diff: deterministic behavioral delta runtime for governed semantic pipelines."""

from pi_semantic_diff.deltas import (
    compute_auth_deltas,
    compute_dependency_deltas,
    compute_drift_score,
    compute_endpoint_deltas,
    compute_replay_surface_deltas,
    compute_semantic_delta_score,
    compute_structural_delta_score,
)
from pi_semantic_diff.models import (
    AuthDelta,
    AuthInvariant,
    DependencyDelta,
    DependencyGraph,
    EndpointDelta,
    FieldDelta,
    ReplaySurfaceDelta,
    SemanticDiffReport,
    SemanticField,
    SemanticIRTrace,
    StateEdge,
)
from pi_semantic_diff.runtime import DiffBounds, DiffRuntime

__version__ = "0.1.0"
