"""Schema Gate.

Every worker output passes through schema validation.
Invalid schema -> INVALID_OUTPUT -> HARD_HALT.

No direct worker-to-worker trust. Outputs are guilty until proven structurally valid.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from pi_agent_chain.models import GovernanceViolation, WorkerResponse


# Pre-defined JSON Schema fragments for each worker type.
# Workers return: {"payload": <object>, "type": "TypeName"}
WORKER_OUTPUT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "acquisition_gateway": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
    "structural_extractor": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
    "semantic_typer": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
    "flow_mapper": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
    "spec_synthesizer": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
    "verifier": {
        "type": "object",
        "required": ["payload", "type"],
        "properties": {
            "payload": {"type": "object"},
            "type": {"type": "string"},
        },
    },
}


class SchemaGate:
    """Structural validation of worker outputs against JSON Schema fragments.

    Workers are replaceable. Schemas are invariant.
    """

    def __init__(self, schemas: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.schemas = schemas or WORKER_OUTPUT_SCHEMAS

    def validate(
        self, worker_id: str, payload: Dict[str, Any], worker_response: WorkerResponse
    ) -> Optional[GovernanceViolation]:
        """Validate a worker output against its declared schema.

        Returns None if valid. Returns GovernanceViolation on breach.
        """
        schema = self.schemas.get(worker_id)
        if schema is None:
            # No schema registered for this worker = unrestricted (for extensibility)
            return None

        try:
            self._check_required(schema, payload)
            self._check_types(schema, payload)
        except _SchemaViolation as exc:
            return GovernanceViolation(
                violation_id=str(uuid.uuid4())[:16],
                rule="INVALID_OUTPUT",
                worker_id=worker_id,
                root_goal_id=worker_response.root_goal_id,
                severity="ERROR",
                context={"field": exc.field, "reason": exc.reason, "payload_keys": list(payload.keys())},
                action_taken="HALT",
            )

        return None

    @staticmethod
    def _check_required(schema: Dict[str, Any], payload: Dict[str, Any]) -> None:
        required = schema.get("required", [])
        for key in required:
            if key not in payload:
                raise _SchemaViolation(key, f"Missing required field '{key}'")

    @staticmethod
    def _check_types(schema: Dict[str, Any], payload: Dict[str, Any]) -> None:
        properties = schema.get("properties", {})
        for key, value in payload.items():
            if key in properties:
                expected = properties[key].get("type")
                if expected == "array" and not isinstance(value, list):
                    raise _SchemaViolation(key, f"Expected array, got {type(value).__name__}")
                if expected == "object" and not isinstance(value, dict):
                    raise _SchemaViolation(key, f"Expected object, got {type(value).__name__}")
                if expected == "string" and not isinstance(value, str):
                    raise _SchemaViolation(key, f"Expected string, got {type(value).__name__}")
                if expected == "integer" and not isinstance(value, int):
                    raise _SchemaViolation(key, f"Expected integer, got {type(value).__name__}")
                if expected == "boolean" and not isinstance(value, bool):
                    raise _SchemaViolation(key, f"Expected boolean, got {type(value).__name__}")
                if expected == "number" and not isinstance(value, (int, float)):
                    raise _SchemaViolation(key, f"Expected number, got {type(value).__name__}")


class _SchemaViolation(Exception):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"SchemaViolation: {field} -> {reason}")
