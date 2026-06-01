from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query

from pi_event_fabric.bus.core import DomainEvent, EventBusStorage
from pi_event_fabric.bus.semantic_fabric import PiSemanticEventFabric
from pi_event_fabric.replay.engine import PiExecutionReplayEngine
from pi_micro_agents.orchestrator.scheduler import PiCognitiveExecutionScheduler

router = APIRouter()

# Instantiate shared cognitive substrate components
DB_PATH = os.getenv("PI_EVENT_BUS_DB_PATH", ":memory:")
storage = EventBusStorage(DB_PATH)
semantic_fabric = PiSemanticEventFabric(storage)
replay_engine = PiExecutionReplayEngine(storage)
scheduler = PiCognitiveExecutionScheduler()


@router.get("/lineage/{trace_id}")
async def get_lineage(trace_id: str) -> Dict[str, Any]:
    """Returns the complete causality DAG showing parent/child event nodes."""
    try:
        dag = semantic_fabric.get_causality_dag(trace_id)
        if not dag or not dag.get("nodes"):
            # Fallback: check if we can query by correlation_id to build causality DAG
            events = storage.read_by_correlation(trace_id)
            if events:
                # Try starting from the last event hash in the correlation list
                dag = semantic_fabric.get_causality_dag(events[-1].event_hash)
        return dag
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/scheduler/stats")
async def get_scheduler_stats() -> Dict[str, Any]:
    """Retrieves live scheduler parameters, priority allocations, queue sizes, and speculative execution speedups."""
    try:
        return scheduler.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/replay/binary-search")
async def run_replay_bisect(
    correlation_id: str = Query(..., description="Correlation ID of the trajectory to analyze"),
) -> Dict[str, Any]:
    """Initializes a diagnostic time-travel bisect sequence for a selected execution."""
    try:
        events = storage.read_by_correlation(correlation_id)
        if not events:
            raise HTTPException(status_code=404, detail=f"No events found for correlation ID: {correlation_id}")

        # Basic state builder and validator for diagnostic purposes
        def basic_state_builder(state: Dict[str, Any], event: DomainEvent) -> Dict[str, Any]:
            new_state = state.copy()
            new_state[event.header.event_id] = event.payload

            # Track accumulated risk
            semantic = event.payload.get("_semantic", {})
            if "risk_score" in event.payload:
                new_state["accumulated_risk"] = new_state.get("accumulated_risk", 0.0) + event.payload["risk_score"]
            elif "trust_level" in semantic:
                new_state["accumulated_risk"] = new_state.get("accumulated_risk", 0.0) + (1.0 - semantic["trust_level"])
            return new_state

        def basic_validator(state: Dict[str, Any], event: DomainEvent) -> bool:
            # Violate if accumulated risk exceeds 1.5
            return state.get("accumulated_risk", 0.0) <= 1.5

        initial_state = {"accumulated_risk": 0.0}

        result = replay_engine.bisect_failure(
            events=events, initial_state=initial_state, state_builder=basic_state_builder, validator_fn=basic_validator
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
