"""Abstract base class for all verification engines.

Enforces deterministic, bounded, stateless verification contracts.
No hidden memory. No LLM invocation.
"""

from __future__ import annotations

import abc
from typing import List

from pi_agent_chain.models import BehavioralDelta


class VerificationEngine(abc.ABC):
    """Contamination-free validation boundary.

    Every subclass:
    - consumes a SynthesizedSpec JSON payload
    - optionally consumes execution history traces
    - returns a list of BehavioralDeltas
    - NEVER mutates artifact state
    - NEVER induces unbounded inference
    """

    def __init__(self, seed: int = 1337):
        self.seed = seed

    @abc.abstractmethod
    def verify(self, spec_json: str, history_traces: List[dict]) -> List[BehavioralDelta]:
        """Execute validation and return explicit contradictions/confirmations.

        Parameters
        ----------
        spec_json: str
            JSON-serialized OpenAPI 3.1 specification from the SynthesizedSpec artifact.
        history_traces: List[dict]
            Raw execution traces (packet dicts) from prior pipeline runs or live captures.
        """
        pass
