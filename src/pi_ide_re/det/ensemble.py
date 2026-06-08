"""
ensemble.py - ensemble determinism arbiter (Theme 4, P3 - INVESTIGATE ONLY).

A DETERMINISTIC, OFFLINE scaffold modeled on KikkaSkills/det_ensemble.py's
two-pass shape (fast `generate_candidates` -> strong `select_best`), reframed
for the parity-divergence use case: when the Python and Rust implementations
disagree, deterministically pick a canonical result from a candidate pool using
a pluggable scorer.

IMPORTANT: this makes NO network/LLM calls (unlike the source, which calls
OpenRouter). The point under investigation is the *framework* - pluggable
generator + scorer + a single deterministic selection rule - not a model. The
platform's real correctness gate remains the differential fuzz + Rust<->Python
parity harness; this is an experiment for what to do AFTER a divergence is
detected.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ..graph_schema import content_hash

Generator = Callable[[str, int], List[str]]
Scorer = Callable[[str], Any]


def _default_generator(seed: str, n: int) -> List[str]:
    # deterministic, distinct variants derived from the seed
    return [f"{seed}#{content_hash({'seed': seed, 'i': i})}" for i in range(n)]


def _default_scorer(candidate: str) -> str:
    # arbitrary-but-deterministic: lexicographic by content hash
    return content_hash({"c": candidate})


def generate_candidates(seed: str, n: int = 5, generator: Optional[Generator] = None) -> List[str]:
    gen = generator or _default_generator
    return gen(seed, n)


def select_best(original: str, candidates: List[str], scorer: Optional[Scorer] = None) -> Dict[str, Any]:
    """Deterministically pick the best candidate (lowest score; ties by value)."""
    score_fn = scorer or _default_scorer
    scores = {c: score_fn(c) for c in candidates}
    ranked = sorted(candidates, key=lambda c: (scores[c], c))
    return {
        "best": ranked[0] if ranked else None,
        "ranked": ranked,
        "scores": scores,
        "original": original,
    }


def arbitrate(
    python_output: str,
    rust_output: str,
    candidates: Optional[List[str]] = None,
    scorer: Optional[Scorer] = None,
) -> Dict[str, Any]:
    """On parity divergence, deterministically select a canonical output.

    EXPERIMENTAL. If the two outputs agree, there is no divergence. Otherwise
    pool both (+ any extra candidates) and select via the scorer.
    """
    if python_output == rust_output:
        return {"diverged": False, "winner": python_output, "ranked": [python_output]}
    pool: List[str] = []
    for c in [python_output, rust_output, *(candidates or [])]:
        if c not in pool:
            pool.append(c)
    result = select_best(python_output, pool, scorer=scorer)
    return {"diverged": True, "winner": result["best"], "ranked": result["ranked"], "scores": result["scores"]}
