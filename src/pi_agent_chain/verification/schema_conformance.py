"""Schema Conformance Engine.

Validates that SynthesizedSpec output adheres to OpenAPI 3.1.0 grammar.
Syntactic containment gate. No LLM.
"""

from __future__ import annotations

import json
from typing import List

from pi_agent_chain.models import BehavioralDelta
from pi_agent_chain.verification.base import VerificationEngine


class SchemaConformanceEngine(VerificationEngine):
    """Structural validation of compiled OpenAPI specifications.

    Detects:
    - Missing/invalid `openapi` version string
    - Missing/invalid `paths` dict
    - Malformed JSON
    """

    def verify(self, spec_json: str, history_traces: List[dict]) -> List[BehavioralDelta]:
        deltas: List[BehavioralDelta] = []
        try:
            spec_data = json.loads(spec_json)
        except json.JSONDecodeError as exc:
            deltas.append(
                BehavioralDelta(
                    path="root",
                    action="PARSE_JSON",
                    observed_status=500,
                    expected_status=200,
                    contradiction_detected=True,
                    message=f"JSON Parse failure during conformance: {exc}",
                )
            )
            return deltas

        if "openapi" not in spec_data or not str(spec_data.get("openapi", "")).startswith("3.1"):
            deltas.append(
                BehavioralDelta(
                    path="root.openapi",
                    action="SYNTAX_CHECK",
                    observed_status=500,
                    expected_status=200,
                    contradiction_detected=True,
                    message="Missing or invalid OpenAPI 3.1.0 version string.",
                )
            )

        if "paths" not in spec_data or not isinstance(spec_data.get("paths"), dict):
            deltas.append(
                BehavioralDelta(
                    path="root.paths",
                    action="SYNTAX_CHECK",
                    observed_status=500,
                    expected_status=200,
                    contradiction_detected=True,
                    message="Paths structure is missing or malformed.",
                )
            )

        if "info" not in spec_data or not isinstance(spec_data.get("info"), dict):
            deltas.append(
                BehavioralDelta(
                    path="root.info",
                    action="SYNTAX_CHECK",
                    observed_status=500,
                    expected_status=200,
                    contradiction_detected=True,
                    message="Missing info block (title, version) required by OpenAPI 3.1.0.",
                )
            )

        return deltas
