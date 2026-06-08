"""Pi-ConsensusBreaker Agent Capability.

Systematically evaluates and scores prompt divergence across multiple
LLM responses, identifying semantic and structural alignment gaps.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ModelResponse(BaseModel):
    model_name: str
    content: str
    parsed_json: Optional[Dict[str, Any]] = None
    model_config = {"frozen": True}


class DivergenceReport(BaseModel):
    prompt: str
    responses: List[ModelResponse] = Field(default_factory=list)
    semantic_divergence: float = 0.0
    structural_divergence: float = 0.0
    consensus_divergence_score: float = 0.0
    is_broken: bool = False
    model_config = {"frozen": True}


def simple_token_vector(text: str) -> Dict[str, float]:
    """Generates a simple normalized token vector for cosine math."""
    words = [w.strip(".,!?\"'()").lower() for w in text.split() if len(w) > 2]
    vector: Dict[str, float] = {}
    for word in words:
        vector[word] = vector.get(word, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in vector.values()))
    if norm > 0:
        for k in vector:
            vector[k] /= norm
    return vector


def calculate_cosine_distance(text_a: str, text_b: str) -> float:
    """Calculates pairwise cosine distance between text bags."""
    vec_a = simple_token_vector(text_a)
    vec_b = simple_token_vector(text_b)
    intersection = set(vec_a.keys()) & set(vec_b.keys())
    dot_product = sum(vec_a[w] * vec_b[w] for w in intersection)
    return round(1.0 - float(dot_product), 4)


class PiConsensusBreaker:
    """Pi-ConsensusBreaker Core Evaluator."""

    def __init__(
        self,
        weight_semantic: float = 0.5,
        weight_structural: float = 0.5,
        divergence_threshold: float = 60.0,
    ) -> None:
        self.w_semantic = weight_semantic
        self.w_structural = weight_structural
        self.threshold = divergence_threshold

    def calculate_structural_variance(self, schemas: List[Dict[str, Any]]) -> float:
        """Computes pairwise key mismatch variance across list of parsed JSON structures."""
        if len(schemas) < 2:
            return 0.0

        all_keys = set()
        for s in schemas:
            all_keys.update(s.keys())

        if not all_keys:
            return 0.0

        total_variance = 0.0
        k = len(schemas)

        for i in range(k):
            for j in range(i + 1, k):
                keys_i = set(schemas[i].keys())
                keys_j = set(schemas[j].keys())
                sym_diff = keys_i ^ keys_j
                union = keys_i | keys_j

                if union:
                    total_variance += len(sym_diff) / len(union)

        pairs_count = (k * (k - 1)) / 2.0
        normalized_variance = (total_variance / pairs_count) * 100.0 if pairs_count > 0 else 0.0
        return round(normalized_variance, 2)

    def evaluate_consensus(self, prompt: str, responses: List[ModelResponse]) -> DivergenceReport:
        """Evaluates model responses and calculates the Consensus Divergence Score."""
        k = len(responses)
        if k < 2:
            raise ValueError("ConsensusBreaker requires at least two model responses.")

        # 1. Compute Semantic Divergence
        total_semantic_distance = 0.0
        for i in range(k):
            for j in range(i + 1, k):
                total_semantic_distance += calculate_cosine_distance(responses[i].content, responses[j].content)

        pairs_count = (k * (k - 1)) / 2.0
        avg_semantic_distance = (total_semantic_distance / pairs_count) if pairs_count > 0 else 0.0
        semantic_score = avg_semantic_distance * 100.0

        # 2. Compute Structural Divergence
        json_payloads = [r.parsed_json for r in responses if r.parsed_json is not None]
        structural_score = self.calculate_structural_variance(json_payloads)

        # 3. Compute D_c Score
        dc_score = (self.w_semantic * semantic_score) + (self.w_structural * structural_score)
        dc_score = min(round(dc_score, 2), 100.0)

        is_broken = dc_score >= self.threshold

        return DivergenceReport(
            prompt=prompt,
            responses=responses,
            semantic_divergence=round(semantic_score, 2),
            structural_divergence=structural_score,
            consensus_divergence_score=dc_score,
            is_broken=is_broken,
        )
