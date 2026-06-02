"""The orchestrator write paths stamp the current tenant onto ExecutionTrace.

This closes the write half of the console tenant-isolation finding: previously
PiOrchestrator / ChainExecutionEngine / PipelineDriver built traces with no
tenant_id, so every real audit row defaulted to 'default' and the (correct)
read-side filter never isolated real traffic. Now a trace written inside a
tenant_scope carries that tenant; with no scope it defaults to 'default'.
"""

from __future__ import annotations

from pydantic import BaseModel

import pi_micro_agents.orchestrator.chain_engine as ce
from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.pipeline import PipelineDriver
from pi_agent_chain.tenant_context import tenant_scope
from pi_micro_agents.orchestrator.chain_engine import ChainExecutionEngine
from pi_micro_agents.orchestrator.core import PiOrchestrator
from pi_micro_agents.orchestrator.router import AgentRoute


class _In(BaseModel):
    goal: str = ""


class TestOrchestratorWritePath:
    def test_stamps_current_tenant(self, tmp_path):
        led = StateLedger(str(tmp_path / "o.db"))
        orch = PiOrchestrator(ledger=led)
        with tenant_scope("tenant-a"):
            orch._compile_and_log_output(True, "PiX", 0.0, "s", {}, [], "goal")
        traces = led.get_all()
        assert traces and all(t.tenant_id == "tenant-a" for t in traces)

    def test_defaults_without_scope(self, tmp_path):
        led = StateLedger(str(tmp_path / "o2.db"))
        PiOrchestrator(ledger=led)._compile_and_log_output(True, "PiX", 0.0, "s", {}, [], "goal")
        assert led.get_all()[0].tenant_id == "default"


class TestPipelineWritePath:
    def test_stamps_current_tenant(self, tmp_path):
        led = StateLedger(str(tmp_path / "p.db"))
        drv = PipelineDriver(ledger=led, base_url="http://localhost")
        with tenant_scope("tenant-b"):
            drv._log_trace(trace_id="t1", node_name="n", input_hash="h", raw_output="{}", is_valid=True)
        assert led.get_trace("t1")[0].tenant_id == "tenant-b"


class TestChainEngineWritePath:
    def test_stamps_current_tenant(self, monkeypatch, tmp_path):
        # stub the heavy consensus call so we reach the trace-write deterministically
        monkeypatch.setattr(ce, "run_with_consensus", lambda *a, **k: (True, 0.0, "ok", {}, []))
        led = StateLedger(str(tmp_path / "c.db"))
        engine = ChainExecutionEngine(orchestrator=object(), ledger=led)
        route = AgentRoute(
            agent_name="PiX", keywords=[], agent_class=BaseModel, input_factory=lambda g, c: _In(goal=g)
        )
        with tenant_scope("tenant-c"):
            engine.execute_chain([route], goal="g", context={})
        traces = led.get_all()
        assert traces and all(t.tenant_id == "tenant-c" for t in traces)
