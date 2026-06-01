"""StateLedger persists a tenant_id per trace, and migrates legacy DBs in place."""

from __future__ import annotations

import sqlite3

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import ExecutionTrace

_LEGACY_DDL = """
CREATE TABLE execution_trace (
    id INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL, node_name TEXT NOT NULL,
    input_payload_hash TEXT NOT NULL, llm_seed INTEGER NOT NULL, llm_temperature REAL NOT NULL,
    raw_output TEXT NOT NULL, is_valid_type INTEGER NOT NULL, is_finding INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL, error_message TEXT
)
"""


def _trace(trace_id: str, tenant: str) -> ExecutionTrace:
    return ExecutionTrace(
        trace_id=trace_id,
        node_name="n",
        input_payload_hash="h",
        llm_seed=1,
        llm_temperature=0.0,
        raw_output="{}",
        is_valid_type=True,
        tenant_id=tenant,
    )


def test_ledger_persists_and_returns_tenant(tmp_path):
    led = StateLedger(tmp_path / "l.db")
    led.append(_trace("t1", "tenant-x"))
    assert led.get_trace("t1")[0].tenant_id == "tenant-x"


def test_execution_trace_defaults_tenant_to_default():
    # Orchestrator-internal writes that don't supply a tenant fall back to 'default'.
    assert _trace_default().tenant_id == "default"


def _trace_default() -> ExecutionTrace:
    return ExecutionTrace(
        trace_id="t",
        node_name="n",
        input_payload_hash="h",
        llm_seed=1,
        llm_temperature=0.0,
        raw_output="{}",
        is_valid_type=True,
    )


def test_ledger_migrates_legacy_table_in_place(tmp_path):
    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
    conn.execute(_LEGACY_DDL)
    conn.execute(
        "INSERT INTO execution_trace (trace_id, node_name, input_payload_hash, llm_seed, "
        "llm_temperature, raw_output, is_valid_type, is_finding, timestamp, error_message) "
        "VALUES ('old', 'n', 'h', 1, 0.0, '{}', 1, 0, '2026-01-01T00:00:00', NULL)"
    )
    conn.commit()
    conn.close()

    # Opening the ledger must add the tenant_id column without losing rows.
    led = StateLedger(db)
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(execution_trace)").fetchall()}
    assert "tenant_id" in cols
    assert led.get_trace("old")[0].tenant_id == "default"  # legacy rows default
    led.append(_trace("new", "tenant-z"))
    assert led.get_trace("new")[0].tenant_id == "tenant-z"
