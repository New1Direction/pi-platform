"""src/pi_runtime/tui/event_bus.py

Event bus for PI Execution Cockpit TUI.
Emits events conforming to: docs/events/cockpit-event-schema.json

If the Rust models.rs deserialization breaks, update the schema first,
then both sides — the schema is the contract, not the individual files.

Lightweight internal event bus for real-time TUI updates.
"""

from typing import Any, Callable, Dict, List


class ExecutionEventBus:
    def __init__(self):
        self.subscribers: List[Callable] = []

    def subscribe(self, callback: Callable):
        self.subscribers.append(callback)

    def emit(self, event_type: str, data: Dict[str, Any]):
        for callback in self.subscribers:
            callback(event_type, data)
