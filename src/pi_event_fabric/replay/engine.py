from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from pi_event_fabric.bus.core import DomainEvent, EventBusStorage, EventType, PartitionKey

logger = logging.getLogger("pi_platform.replay")


class PiExecutionReplayEngine:
    """Deterministic Replay and Time-Travel Engine for cognitive agent trajectories."""

    def __init__(self, storage: EventBusStorage) -> None:
        self.storage = storage
        self.mock_providers: Dict[str, Callable[..., Any]] = {}

    def register_mock_provider(self, name: str, provider_fn: Callable[..., Any]) -> None:
        """Registers a deterministic mock provider for API/tool execution side-effects."""
        self.mock_providers[name] = provider_fn

    def get_mocked_response(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Retrieves a registered mock response if available, else returns None."""
        if name in self.mock_providers:
            return self.mock_providers[name](*args, **kwargs)
        logger.warning(f"No mock provider registered for side-effect: {name}")
        return None

    def load_agent_latest_snapshot(
        self, agent_id: str, correlation_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieves the latest cryptographically signed snapshot for an agent."""
        events = self.storage.get_partition_tail(PartitionKey.SNAPSHOTS, n=200)

        # Search backwards for the most recent snapshot matching agent_id (and optional correlation_id)
        for event in reversed(events):
            if event.header.event_type == EventType.SNAPSHOT_STORED:
                payload = event.payload
                if payload.get("agent_id") == agent_id:
                    if correlation_id is None or event.header.correlation_id == correlation_id:
                        return payload.get("agent_state")
        return None

    def replay_trajectory(
        self,
        events: List[DomainEvent],
        initial_state: Dict[str, Any],
        state_builder: Callable[[Dict[str, Any], DomainEvent], Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Replays a series of events from an initial state, yielding the sequence of intermediate states."""
        state_history = [initial_state.copy()]
        current_state = initial_state.copy()

        for event in events:
            current_state = state_builder(current_state, event)
            state_history.append(current_state.copy())

        return state_history

    def bisect_failure(
        self,
        events: List[DomainEvent],
        initial_state: Dict[str, Any],
        state_builder: Callable[[Dict[str, Any], DomainEvent], Dict[str, Any]],
        validator_fn: Callable[[Dict[str, Any], DomainEvent], bool],
    ) -> Dict[str, Any]:
        """Performs a binary-search over a trajectory to find the first event violating governance or correctness validation."""
        if not events:
            return {"status": "EMPTY_TRAJECTORY", "failed_index": -1}

        low = 0
        high = len(events) - 1
        first_failed_index = -1

        while low <= high:
            mid = (low + high) // 2

            # Step-replay from start up to and including 'mid'
            state = initial_state.copy()
            failed = False
            for i in range(mid + 1):
                ev = events[i]
                state = state_builder(state, ev)
                if not validator_fn(state, ev):
                    failed = True
                    break

            if failed:
                first_failed_index = mid
                high = mid - 1  # Seek earlier violation
            else:
                low = mid + 1  # Seek later violation

        if first_failed_index != -1:
            failed_event = events[first_failed_index]
            return {
                "status": "FAILURE_ISOLATED",
                "failed_index": first_failed_index,
                "failed_event_id": failed_event.header.event_id,
                "failed_event_hash": failed_event.event_hash,
                "failed_event_type": failed_event.header.event_type.value,
                "failed_payload": failed_event.payload,
            }

        return {
            "status": "NO_FAILURE_DETECTED",
            "failed_index": -1,
        }
