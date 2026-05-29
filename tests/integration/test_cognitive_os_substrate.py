from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import pytest
from fastapi.testclient import TestClient

from pi_console.main import app
from pi_event_fabric.bus.core import EventBusStorage, EventType, PartitionKey
from pi_event_fabric.bus.semantic_fabric import (
    CausalChainBreakError,
    PiSemanticEventFabric,
    TrustEnforcementError,
)
from pi_event_fabric.replay.engine import PiExecutionReplayEngine
from pi_micro_agents.orchestrator.governance_kernel import (
    GovernanceViolationError,
    PiRuntimeGovernanceKernel,
)
from pi_micro_agents.orchestrator.scheduler import (
    AgentExecutionClass,
    PiCognitiveExecutionScheduler,
    SchedulerTask,
)

if TYPE_CHECKING:
    from pi_event_fabric.bus.core import DomainEvent

# ────────────────────────────────────────────────────────
#  1. Scheduler Tests
# ────────────────────────────────────────────────────────


def test_scheduler_priority_and_backpressure() -> None:
    # 0 disables degradation, but let's test lower boundary degradation
    scheduler = PiCognitiveExecutionScheduler(max_workers=2, backpressure_threshold=2)

    run_order = []

    def dummy_task(task: SchedulerTask) -> dict:
        time.sleep(0.05)
        run_order.append(task.priority)
        return {"success": True, "priority": task.priority}

    # Submit 2 tasks to fill workers/queue
    f1 = scheduler.schedule(
        "Task 1", AgentExecutionClass.SOFT_REAL_TIME, priority=10, payload={}, execute_fn=dummy_task
    )
    f2 = scheduler.schedule("Task 2", AgentExecutionClass.SOFT_REAL_TIME, priority=5, payload={}, execute_fn=dummy_task)

    # 3rd task will breach backpressure threshold and trigger degradation immediately
    f3 = scheduler.schedule("Task 3", AgentExecutionClass.SOFT_REAL_TIME, priority=1, payload={}, execute_fn=dummy_task)

    res3 = f3.result()
    assert res3["status"] == "DEGRADED_FALLBACK"
    assert res3["success"] is True

    f1.result()
    f2.result()

    stats = scheduler.get_stats()
    assert stats["backpressure_tripped"] > 0
    assert stats["degradations_applied"] > 0


def test_scheduler_speculative_execution() -> None:
    scheduler = PiCognitiveExecutionScheduler(max_workers=4)

    tasks = [
        SchedulerTask(goal="Solve A", execution_class=AgentExecutionClass.VERIFIER, priority=2),
        SchedulerTask(goal="Solve B", execution_class=AgentExecutionClass.HARD_REAL_TIME, priority=5),
    ]

    def spec_task(task: SchedulerTask) -> dict:
        if "Solve A" in task.goal:
            return {"success": True, "risk_score": 0.1, "anomalies_detected": ["mild_warning"]}
        return {"success": True, "risk_score": 0.4}

    res = scheduler.run_speculative(tasks, spec_task)
    assert res["success"] is True
    # Average of 0.1 and 0.4
    assert res["risk_score"] == pytest.approx(0.25)
    assert "mild_warning" in res["anomalies_detected"]
    assert res["branches_completed"] == 2


# ────────────────────────────────────────────────────────
#  2. Semantic Event Bus Tests
# ────────────────────────────────────────────────────────


def test_semantic_event_fabric_trust_and_causality(tmp_path) -> None:
    db_file = str(tmp_path / "events.db")
    storage = EventBusStorage(db_file)
    fabric = PiSemanticEventFabric(storage, min_trust_threshold=0.5)

    # 1. Test trust boundary enforcement
    with pytest.raises(TrustEnforcementError):
        fabric.append_semantic(
            event_type=EventType.WORKER_COMPLETED,
            partition_key=PartitionKey.WORKERS,
            payload={"msg": "low trust"},
            semantic_intent="test",
            execution_lineage=["agent1"],
            trust_level=0.4,  # Below threshold 0.5
            causality_chain=[],
            schema_version="1.0.0",
            policy_classification="standard",
            tenant_id="tenant_A",
            actor_id="actor_1",
            correlation_id="corr_1",
            bypass_causal_check=True,
        )

    # 2. Append valid parent event
    parent_event = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"msg": "root"},
        semantic_intent="root_intent",
        execution_lineage=["agent1"],
        trust_level=0.9,
        causality_chain=[],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="corr_1",
        bypass_causal_check=True,
    )
    parent_hash = parent_event.event_hash
    assert fabric.check_event_hash_exists(parent_hash) is True

    # 3. Append child with valid causality
    child_event = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"msg": "child"},
        semantic_intent="child_intent",
        execution_lineage=["agent1", "agent2"],
        trust_level=0.8,
        causality_chain=[parent_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="corr_1",
    )
    assert child_event.payload["_semantic"]["causality_chain"] == [parent_hash]

    # 4. Append child with non-existent parent hash (breaks causality)
    with pytest.raises(CausalChainBreakError):
        fabric.append_semantic(
            event_type=EventType.WORKER_COMPLETED,
            partition_key=PartitionKey.WORKERS,
            payload={"msg": "broken"},
            semantic_intent="broken_intent",
            execution_lineage=["agent1"],
            trust_level=0.9,
            causality_chain=["non_existent_hash"],
            schema_version="1.0.0",
            policy_classification="standard",
            tenant_id="tenant_A",
            actor_id="actor_1",
            correlation_id="corr_1",
        )


def test_semantic_event_fabric_dag_and_snapshot(tmp_path) -> None:
    db_file = str(tmp_path / "events_dag.db")
    storage = EventBusStorage(db_file)
    fabric = PiSemanticEventFabric(storage, min_trust_threshold=0.0)

    # Build causality chain: e1 -> e2 -> e3
    e1 = fabric.append_semantic(
        event_type=EventType.WORKER_DISPATCHED,
        partition_key=PartitionKey.WORKERS,
        payload={"step": 1},
        semantic_intent="start",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="c_1",
        bypass_causal_check=True,
    )
    e2 = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"step": 2},
        semantic_intent="middle",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[e1.event_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="c_1",
    )
    e3 = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"step": 3},
        semantic_intent="end",
        execution_lineage=["agent2"],
        trust_level=1.0,
        causality_chain=[e2.event_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="c_1",
    )

    dag = fabric.get_causality_dag(e3.event_hash)
    assert len(dag["nodes"]) == 3
    assert len(dag["edges"]) == 2

    # Verify agent state checkpoint snapshotting
    snapshot_event = fabric.write_agent_snapshot(
        agent_id="my_agent", state={"counter": 42, "status": "idle"}, correlation_id="c_1"
    )
    assert snapshot_event.header.event_type == EventType.SNAPSHOT_STORED
    assert "state_signature" in snapshot_event.payload


# ────────────────────────────────────────────────────────
#  3. Replay and Time-Travel Engine Tests
# ────────────────────────────────────────────────────────


def test_replay_engine_bisection_and_mocks(tmp_path) -> None:
    db_file = str(tmp_path / "replay.db")
    storage = EventBusStorage(db_file)
    fabric = PiSemanticEventFabric(storage)
    engine = PiExecutionReplayEngine(storage)

    # Register side-effect mock
    engine.register_mock_provider("external_api", lambda x: f"mocked_{x}")
    assert engine.get_mocked_response("external_api", "val") == "mocked_val"

    # Write a series of events for correlation ID 'replay_1'
    # We will simulate risk accumulation: e1(risk=0.5), e2(risk=0.6), e3(risk=0.8) -> cumulative 1.9 > threshold 1.5
    e1 = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"risk_score": 0.5},
        semantic_intent="step_1",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="replay_1",
        bypass_causal_check=True,
    )
    e2 = fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"risk_score": 0.6},
        semantic_intent="step_2",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[e1.event_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="replay_1",
    )
    fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"risk_score": 0.8},
        semantic_intent="step_3",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[e2.event_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="replay_1",
    )

    # Perform binary-search failure isolation
    events = storage.read_by_correlation("replay_1")
    assert len(events) == 3

    def test_state_builder(state: dict, event: DomainEvent) -> dict:
        new_state = state.copy()
        new_state["risk"] = new_state.get("risk", 0.0) + event.payload.get("risk_score", 0.0)
        return new_state

    def test_validator(state: dict, event: DomainEvent) -> bool:
        # Fails if risk exceeds 1.0
        return state.get("risk", 0.0) <= 1.0

    bisect_result = engine.bisect_failure(
        events=events, initial_state={"risk": 0.0}, state_builder=test_state_builder, validator_fn=test_validator
    )

    # e1 (0.5 <= 1.0) -> PASS
    # e2 (0.5+0.6 = 1.1 > 1.0) -> FAIL! So first failure index must be 1 (e2)
    assert bisect_result["status"] == "FAILURE_ISOLATED"
    assert bisect_result["failed_index"] == 1
    assert bisect_result["failed_event_id"] == e2.header.event_id


# ────────────────────────────────────────────────────────
#  4. Governance Kernel Tests
# ────────────────────────────────────────────────────────


def test_governance_kernel_boundaries() -> None:
    kernel = PiRuntimeGovernanceKernel(max_time_ms=100.0, max_tokens=1000, min_trust_rating=0.8)

    # 1. Enforce budgets
    kernel.enforce_budgets(50.0, 500)  # Safe
    with pytest.raises(GovernanceViolationError):
        kernel.enforce_budgets(120.0, 500)  # Time violation

    with pytest.raises(GovernanceViolationError):
        kernel.enforce_budgets(50.0, 1500)  # Token violation

    # 2. Enforce AST safety gates
    kernel.evaluate_ast_safety("x = 1 + 2")  # Safe
    with pytest.raises(GovernanceViolationError):
        kernel.evaluate_ast_safety("import socket\nsocket.connect()")  # Unauthorized import

    with pytest.raises(GovernanceViolationError):
        kernel.evaluate_ast_safety("import os\nos.system('rm -rf /')")  # Unauthorized import

    # 3. Enforce Trust Ratings
    kernel.check_trust_clearance(0.9)  # Safe
    with pytest.raises(GovernanceViolationError):
        kernel.check_trust_clearance(0.5)  # Under clearance


# ────────────────────────────────────────────────────────
#  5. Transparency FastAPI Endpoints Tests
# ────────────────────────────────────────────────────────


def test_transparency_api_endpoints(tmp_path) -> None:
    # Use standard FastAPI TestClient on mounted router app
    client = TestClient(app)

    # Set up environmental DB path so transparency router writes/reads to the same SQLite path
    db_file = str(tmp_path / "console_integration.db")
    os.environ["PI_EVENT_BUS_DB_PATH"] = db_file

    # Reload transparency routers models (or instantiate a separate fabric)
    from pi_console.routers.transparency_router import semantic_fabric, storage

    # Clean storage pointer setup to point to new DB
    storage.__init__(db_file)
    semantic_fabric.__init__(storage)

    # 1. Verify scheduler stats endpoint
    response = client.get("/api/v1/transparency/scheduler/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "total_scheduled" in stats
    assert "active_tasks_count" in stats

    # 2. Write simple lineage chain and verify lineage endpoint
    e1 = semantic_fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"status": "init"},
        semantic_intent="init",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="console_c_1",
        bypass_causal_check=True,
    )
    e2 = semantic_fabric.append_semantic(
        event_type=EventType.WORKER_COMPLETED,
        partition_key=PartitionKey.WORKERS,
        payload={"status": "done", "risk_score": 1.6},  # breach 1.5 risk
        semantic_intent="finish",
        execution_lineage=["agent1"],
        trust_level=1.0,
        causality_chain=[e1.event_hash],
        schema_version="1.0.0",
        policy_classification="standard",
        tenant_id="tenant_A",
        actor_id="actor_1",
        correlation_id="console_c_1",
    )

    response = client.get(f"/api/v1/transparency/lineage/{e2.event_hash}")
    assert response.status_code == 200
    dag = response.json()
    assert len(dag["nodes"]) == 2
    assert len(dag["edges"]) == 1

    # 3. Verify replay binary search endpoint
    response = client.get("/api/v1/transparency/replay/binary-search?correlation_id=console_c_1")
    assert response.status_code == 200
    bisect = response.json()
    # e1 (risk=0) -> PASS
    # e2 (accumulated risk = 1.6 > 1.5) -> FAIL at index 1
    assert bisect["status"] == "FAILURE_ISOLATED"
    assert bisect["failed_index"] == 1
    assert bisect["failed_event_id"] == e2.header.event_id
