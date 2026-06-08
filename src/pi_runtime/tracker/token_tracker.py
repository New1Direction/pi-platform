"""
Real Token Tracker — per-agent, per-mission token accounting.

This module records ACTUAL token usage reported by the model provider.
No simulated or placeholder numbers allowed.

Usage pattern:
    tracker = TokenTracker(mission_id="orbstack-re-001")
    tracker.record(agent_id="network-grpc-specialist", input_tokens=312, output_tokens=87)
    summary = tracker.get_mission_summary()
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List


@dataclass
class TokenRecord:
    """Single real token usage event."""

    agent_id: str
    mission_id: str
    input_tokens: int
    output_tokens: int
    model_tier: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TokenTracker:
    """
    Tracks real token consumption per agent.

    All numbers come from actual model responses.
    Never fabricates or estimates.
    """

    def __init__(self, mission_id: str):
        self.mission_id = mission_id
        self._records: List[TokenRecord] = []
        self._totals: Dict[str, Dict[str, int]] = {}  # agent_id -> {input, output, total}

    def record(
        self,
        agent_id: str,
        input_tokens: int,
        output_tokens: int,
        model_tier: str,
    ) -> TokenRecord:
        """Record a real token usage event. All values must be non-negative integers from the provider."""
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("Token counts must be non-negative (real usage only)")

        rec = TokenRecord(
            agent_id=agent_id,
            mission_id=self.mission_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model_tier=model_tier,
        )
        self._records.append(rec)

        # Update running totals
        if agent_id not in self._totals:
            self._totals[agent_id] = {"input": 0, "output": 0, "total": 0}
        self._totals[agent_id]["input"] += input_tokens
        self._totals[agent_id]["output"] += output_tokens
        self._totals[agent_id]["total"] += input_tokens + output_tokens

        return rec

    def get_agent_total(self, agent_id: str) -> Dict[str, int]:
        """Return real totals for one agent in this mission."""
        return self._totals.get(agent_id, {"input": 0, "output": 0, "total": 0}).copy()

    def get_mission_summary(self) -> Dict[str, object]:
        """Return complete real token picture for the entire mission."""
        grand_total = sum(r.input_tokens + r.output_tokens for r in self._records)
        return {
            "mission_id": self.mission_id,
            "total_tokens": grand_total,
            "per_agent": {aid: self.get_agent_total(aid) for aid in self._totals},
            "record_count": len(self._records),
        }

    def get_records_for_agent(self, agent_id: str) -> List[TokenRecord]:
        """All real records for a specific agent."""
        return [r for r in self._records if r.agent_id == agent_id]
