"""Differential Replay Engine.

Compares historical execution traces against the synthesized OpenAPI spec.
Identifies route mismatches, missing endpoints, and status code violations.
"""

from __future__ import annotations

import json
from typing import List

from pi_agent_chain.models import BehavioralDelta
from pi_agent_chain.verification.base import VerificationEngine


class DifferentialReplayEngine(VerificationEngine):
    """Replays captured traffic against the spec to detect behavioral drift.

    Each trace must expose:
        {"packet": {"uri": "...", "method": "GET", "response_status": 200}}
    """

    def verify(self, spec_json: str, history_traces: List[dict]) -> List[BehavioralDelta]:
        deltas: List[BehavioralDelta] = []

        try:
            spec = json.loads(spec_json)
            paths = spec.get("paths", {})
        except Exception:
            return deltas

        for trace in history_traces:
            packet = trace.get("packet", {})
            uri = packet.get("uri", "").split("?")[0]
            method = packet.get("method", "").lower()
            observed_status = packet.get("response_status", 0)

            spec_path = paths.get(uri, {})
            spec_method = spec_path.get(method, {})

            if not spec_method:
                deltas.append(
                    BehavioralDelta(
                        path=f"paths.{uri}.{method}",
                        action="ROUTE_MATCH",
                        observed_status=observed_status,
                        expected_status=404,
                        contradiction_detected=True,
                        message=f"Recorded endpoint {method.upper()} {uri} absent from synthesized spec.",
                    )
                )
                continue

            responses = spec_method.get("responses", {})
            if str(observed_status) not in responses:
                expected_status = int(list(responses.keys())[0]) if responses else 200
                deltas.append(
                    BehavioralDelta(
                        path=f"paths.{uri}.{method}.responses.{observed_status}",
                        action="STATUS_MATCH",
                        observed_status=observed_status,
                        expected_status=expected_status,
                        contradiction_detected=True,
                        message=f"Observed status {observed_status} violates spec contract {list(responses.keys())}.",
                    )
                )

        return deltas
