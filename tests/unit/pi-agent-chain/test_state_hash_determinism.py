"""The ledger state_hash (the user-facing determinism receipt) must ignore
wall-clock latency telemetry.

Finding: compute_state_hash stripped only the top-level per-step `timestamp`, but
each step's `output` (raw_output) JSON embeds `_latency_metrics` (perf_counter
floats). So for any real orchestrator run the state_hash changed every time —
'same input -> same state hash' was false in production.
"""

from __future__ import annotations

import json

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import ExecutionTrace


def _trace(raw_output: str) -> ExecutionTrace:
    return ExecutionTrace(
        trace_id="t",
        node_name="n",
        input_payload_hash="h",
        llm_seed=1,
        llm_temperature=0.0,
        raw_output=raw_output,
        is_valid_type=True,
    )


def _state_hash_with_latency(execution_ms: float) -> str:
    led = StateLedger()  # :memory:
    led.append(
        _trace(
            json.dumps(
                {
                    "result": "ok",
                    "_latency_metrics": {"execution_ms": execution_ms, "routing_ms": execution_ms / 2},
                    "_cache_hit": False,
                }
            )
        )
    )
    return led.compute_state_hash("t")


def test_state_hash_ignores_wall_clock_latency():
    assert _state_hash_with_latency(10.0) == _state_hash_with_latency(987.6)


def test_state_hash_still_reflects_logical_output():
    a = StateLedger()
    a.append(_trace(json.dumps({"result": "A"})))
    b = StateLedger()
    b.append(_trace(json.dumps({"result": "B"})))
    assert a.compute_state_hash("t") != b.compute_state_hash("t")
