"""Integration tests for the Pi-ConsensusBreaker Agent module."""

from __future__ import annotations

import pytest

from pi_semantic_radius import (
    PiConsensusBreaker,
    ModelResponse,
    DivergenceReport,
)
from pi_semantic_radius.consensus_breaker import (
    simple_token_vector,
    calculate_cosine_distance,
)


def test_cosine_similarity_math():
    """Verify that bag-of-words token vectors and cosine distance are calculated correctly."""
    text_1 = "This is a very stable test payload."
    text_2 = "This is a very stable test payload."
    text_3 = "Complete logical mismatch with zero intersecting vocabulary."

    # Identical strings must yield 0 distance (perfect similarity)
    dist_self = calculate_cosine_distance(text_1, text_2)
    assert dist_self == 0.0

    # Totally different strings must yield 1.0 distance (zero similarity)
    dist_diff = calculate_cosine_distance(text_1, text_3)
    assert dist_diff == 1.0


def test_structural_variance_scoring():
    """Verify that the key presence variance score maps key discrepancies accurately."""
    breaker = PiConsensusBreaker()

    # Case A: Identical schemas (variance must be 0)
    schema_1 = {"id": "1", "name": "test"}
    schema_2 = {"id": "2", "name": "dev"}
    var_zero = breaker.calculate_structural_variance([schema_1, schema_2])
    assert var_zero == 0.0

    # Case B: Discrepant schemas
    schema_3 = {"id": "3"}  # missing 'name'
    schema_4 = {"transaction_id": "4", "status": "active"}  # complete mismatch
    var_mismatch = breaker.calculate_structural_variance([schema_3, schema_4])
    assert var_mismatch > 50.0  # High structural discrepancy


def test_consensus_divergence_evaluation():
    """Verify that Consensus Divergence Scores (D_c) identify broken model consensus."""
    breaker = PiConsensusBreaker(weight_semantic=0.6, weight_structural=0.4, divergence_threshold=50.0)

    prompt = "Create active transaction"

    # Case 1: Consensual/stable mock responses (identical structure and meaning)
    responses_stable = [
        ModelResponse(
            model_name="GPT-4",
            content="Active transaction created.",
            parsed_json={"id": "abc", "status": "active"}
        ),
        ModelResponse(
            model_name="Claude-3",
            content="Created active transaction successfully.",
            parsed_json={"id": "abc", "status": "active"}
        )
    ]
    report_stable = breaker.evaluate_consensus(prompt, responses_stable)
    assert report_stable.is_broken is False
    assert report_stable.consensus_divergence_score < breaker.threshold

    # Case 2: Divergent responses (mismatched schema keys and contradicting content)
    responses_divergent = [
        ModelResponse(
            model_name="GPT-4",
            content="Active transaction created successfully.",
            parsed_json={"id": "abc", "status": "active"}
        ),
        ModelResponse(
            model_name="Gemini-1.5",
            content="Transaction creation failed.",
            parsed_json={"error": "failed", "code": 500}
        )
    ]
    report_divergent = breaker.evaluate_consensus(prompt, responses_divergent)
    assert report_divergent.is_broken is True
    assert report_divergent.consensus_divergence_score >= breaker.threshold

