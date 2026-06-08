"""
src/pi_runtime/skills/stealth_browser_researcher/bridge.py

Orchestration bridge connecting the stealth browser researcher skill
to the core pi-agent-chain state transition architecture.
Includes real-time event pulsing for the PI-Execution Cockpit.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from src.pi_runtime.tui.event_bus import ExecutionEventBus

from .skill import StealthBrowserResearcher

logger = logging.getLogger("pi_runtime.chain.drivers.browser_bridge")


class BrowserResearcherChainDriver:
    def __init__(self, event_bus: Optional[ExecutionEventBus] = None):
        self.researcher = StealthBrowserResearcher()
        self.bus = event_bus

    def _pulse(self, event_type: str, data: Dict[str, Any]):
        """Internal helper to push telemetry to the cockpit."""
        if self.bus:
            self.bus.emit(event_type, data)

    def execute_chain_step(self, artifact_payload: Dict[str, Any]) -> Dict[str, Any]:
        objective = artifact_payload.get("objective")
        artifact_id = artifact_payload.get("artifact_id")

        if not objective:
            return {"next_state": "ABORTED", "error": "Missing objective."}

        # Pulse A: Artifact Started
        self._pulse("artifact_started", {"artifact_id": artifact_id, "domain": "browser_recon", "objective": objective})

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        def step_callback(step_data: Dict[str, Any]):
            pulse_data = {**step_data, "artifact_id": artifact_id}
            # Pulse snapshot pruning metrics to the cockpit
            if step_data.get("snapshot_mode"):
                pulse_data["snapshot_metrics"] = {
                    "mode": step_data["snapshot_mode"],
                    "cut_ratio": step_data.get("snapshot_cut_ratio"),
                }
            self._pulse("step_progress", pulse_data)

        skill_output = loop.run_until_complete(self.researcher.run(objective=objective, on_step=step_callback))

        # Pulse C: Execution Complete
        result = self._map_output_to_chain_state(skill_output, artifact_payload)
        self._pulse(
            "execution_complete",
            {
                "artifact_id": artifact_id,
                "status": result["next_state"],
                "telemetry": skill_output.get("telemetry", {}),
            },
        )

        return result

    def _map_output_to_chain_state(
        self, skill_output: Dict[str, Any], original_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        status = skill_output.get("status")

        updated_artifact = {
            "origin_artifact_id": original_payload.get("artifact_id"),
            "steps_executed": skill_output.get("steps_taken", 0),
            "browser_history": skill_output.get("history", []),
        }

        if status == "EXTRACTING":
            return {
                "next_state": "INFERRED",
                "artifact": {
                    **updated_artifact,
                    "session_handle": skill_output.get("session_id"),
                    "resolution_status": "DATA_FOUND",
                },
            }

        elif status == "YIELD_TO_OPERATOR":
            return {
                "next_state": "SUSPENDED",
                "artifact": {
                    **updated_artifact,
                    "session_handle": skill_output.get("session_id"),
                    "resolution_status": "OPERATOR_INTERVENTION_REQUIRED",
                },
            }

        else:
            return {
                "next_state": "ABORTED",
                "artifact": {
                    **updated_artifact,
                    "telemetry": skill_output.get("telemetry", {}),
                    "resolution_status": "PURGED_AND_HALTED",
                },
            }
