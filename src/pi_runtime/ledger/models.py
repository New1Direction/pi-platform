from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentState(str, Enum):
    UNASSIGNED = "UNASSIGNED"
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"
    COMMITTED = "COMMITTED"
    ARCHIVED = "ARCHIVED"


class LedgerEntry(BaseModel):
    """Immutable ledger entry for PI Agents Analysis Squad.

    All communication between agents MUST go through these records.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: UUID
    actor_id: str = Field(min_length=3, max_length=64)
    from_state: AgentState
    to_state: AgentState
    evidence_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    timestamp: datetime
    provenance: list[UUID] = Field(default_factory=list)
    entropy_delta: int = Field(le=0, description="Must be non-positive (entropy must not increase)")

    def model_post_init(self, __context: Any) -> None:
        # Ensure evidence_hash is always lowercase
        object.__setattr__(self, "evidence_hash", self.evidence_hash.lower())

    def is_valid_transition(self) -> bool:
        """Simple state machine validation - can be expanded later."""
        valid_transitions = {
            AgentState.UNASSIGNED: [AgentState.OBSERVED],
            AgentState.OBSERVED: [AgentState.INFERRED],
            AgentState.INFERRED: [AgentState.VERIFIED],
            AgentState.VERIFIED: [AgentState.COMMITTED],
            AgentState.COMMITTED: [AgentState.ARCHIVED],
        }
        return self.to_state in valid_transitions.get(self.from_state, [])
