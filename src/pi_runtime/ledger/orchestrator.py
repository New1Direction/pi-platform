import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from .models import AgentState, LedgerEntry
from .store import LedgerStore
from .validator import validator

_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_target(target: str) -> str:
    """
    Reject any target that could escape the inbox/brain root via path traversal
    (e.g. '../', absolute paths, embedded slashes, NUL bytes). Returns the
    cleaned target on success.
    """
    if not isinstance(target, str) or not _SAFE_TARGET_RE.match(target):
        raise ValueError(f"invalid target identifier: {target!r}; expected [A-Za-z0-9_-]{{1,64}}")
    return target


class TaskPayload:
    """Bounded task given to a specialized subagent.

    Subagents receive exactly this payload and must return a new LedgerEntry.
    No direct communication between subagents is allowed.
    """

    def __init__(
        self,
        task_id: UUID,
        actor_id: str,
        current_state: AgentState,
        objective: str,
        input_artifact_path: Optional[str] = None,
        instructions: str = "",
    ):
        self.task_id = task_id
        self.actor_id = actor_id
        self.current_state = current_state
        self.objective = objective
        self.input_artifact_path = input_artifact_path
        self.instructions = instructions
        self.created_at = datetime.now(timezone.utc)


class SquadOrchestrator:
    """Central (but strictly governed) orchestrator for the PI Agents Analysis Squad.

    Responsibilities:
    - Read current ledger state
    - Determine next valid transition
    - Emit a tightly bounded TaskPayload to exactly one specialized subagent
    - Record the resulting LedgerEntry back to the store
    - Never perform the work of any specialized agent itself
    """

    def __init__(self, store: LedgerStore):
        self.store = store
        self.specialists = {
            AgentState.OBSERVED: "network-grpc-specialist",
            AgentState.INFERRED: "serialization-extractor",
            AgentState.VERIFIED: "binary-static-analyst",
            AgentState.COMMITTED: "client-codegen-specialist",
        }

    def get_next_task(self, target: str = "orbstack") -> Optional[TaskPayload]:
        """Determine and return the next bounded task based on current ledger state.

        This is the only component allowed to read the full ledger and decide what happens next.
        """
        target = _validate_target(target)
        entries = self.store.get_all()

        if not entries:
            # First task: move from UNASSIGNED to OBSERVED (raw artifact ingestion)
            return TaskPayload(
                task_id=uuid4(),
                actor_id="network-grpc-specialist",
                current_state=AgentState.UNASSIGNED,
                objective=f"Observe and capture raw artifacts for target: {target}",
                input_artifact_path=f"PI-Platform/00_Inbox/{target}/",
                instructions="Drop all raw RE artifacts (logs, pcaps, binaries, gRPC captures) into the inbox. "
                "Compute SHA-256 evidence hash. Create initial LedgerEntry with OBSERVED state.",
            )

        last_entry = entries[-1]
        validation = validator.validate_transition(last_entry)

        if not validation.is_valid:
            raise RuntimeError(f"Ledger in invalid state: {validation.reason}. Pipeline halted.")

        next_state = self._get_next_state(last_entry.to_state)
        if not next_state:
            return None  # Terminal state reached

        actor_id = self.specialists.get(next_state, "unknown-specialist")

        objective_map = {
            AgentState.INFERRED: f"Extract structured schemas and protobuf definitions from observed artifacts for {target}",
            AgentState.VERIFIED: f"Perform static analysis, recover types, and validate extracted schemas for {target}",
            AgentState.COMMITTED: f"Generate deterministic, typed Python client code from verified schemas for {target}",
        }

        return TaskPayload(
            task_id=uuid4(),
            actor_id=actor_id,
            current_state=last_entry.to_state,
            objective=objective_map.get(next_state, f"Advance to {next_state} for {target}"),
            input_artifact_path=f"PI-Platform/10_Brain/targets/{target}/",
            instructions=f"Process the current artifacts. Produce output that allows transition to {next_state}. "
            "Return a valid LedgerEntry with proper evidence_hash and non-positive entropy_delta.",
        )

    def _get_next_state(self, current: AgentState) -> Optional[AgentState]:
        """Return the single allowed next state or None if terminal."""
        transition_map = {
            AgentState.UNASSIGNED: AgentState.OBSERVED,
            AgentState.OBSERVED: AgentState.INFERRED,
            AgentState.INFERRED: AgentState.VERIFIED,
            AgentState.VERIFIED: AgentState.COMMITTED,
            AgentState.COMMITTED: AgentState.ARCHIVED,
            AgentState.ARCHIVED: None,
        }
        return transition_map.get(current)

    def record_result(self, entry: LedgerEntry) -> bool:
        """Record the result of a subagent's work into the append-only ledger.

        The ledger is intentionally write-permissive: invalid transitions
        are *appended* but the pipeline halts on the next ``get_next_task``
        via the validator. This separation lets auditors see the bad entry
        rather than losing it to an exception in the writer.
        """
        return self.store.append(entry)

    def get_ledger_summary(self) -> Dict[str, Any]:
        """Return current pipeline status for observability (does not mutate state)."""
        entries = self.store.get_all()
        if not entries:
            return {"status": "UNASSIGNED", "progress": 0, "last_state": None}

        last = entries[-1]
        return {
            "status": last.to_state.value,
            "progress": len(entries),
            "last_state": last.to_state.value,
            "last_actor": last.actor_id,
            "entropy_trend": "decreasing" if last.entropy_delta <= 0 else "invalid",
            "total_entries": len(entries),
        }
