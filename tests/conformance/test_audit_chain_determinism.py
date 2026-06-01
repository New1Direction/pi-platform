"""The append-only audit hash chain must be reproducible across runs.

Finding: AuditLogger.log folded the wall-clock audit_id
(`audit_{tenant}_{actor}_{int(time.time()*1e6)}`) and a datetime.now() timestamp
into the hashed payload, so replaying the same logical sequence of audit events
produced a DIFFERENT audit_hash chain — the "immutable audit ledger" was not
reproducible, and any replay-verification comparing chains saw a false mismatch.
"""

from __future__ import annotations

import os
import tempfile

from pi_production.storage.engine import AuditLogger, ConnectionPool, install_append_only_triggers

# A fixed logical sequence of audit events (no wall-clock inputs).
_EVENTS = [
    ("t1", "actor_1", "API", "snapshot:store", "snapshot", "snap_1", {}, {}, "corr_1"),
    ("t1", "actor_1", "API", "ledger:read", "ledger", "trace_9", {}, {}, "corr_2"),
    ("t1", "actor_2", "WORKER", "replay:run", "replay", "rep_3", {}, {}, "corr_3"),
]


def _chain_for_run() -> list:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        pool = ConnectionPool(path)
        install_append_only_triggers(pool)
        al = AuditLogger(pool)
        for ev in _EVENTS:
            al.log(*ev)
        rows = pool.execute_read("SELECT audit_hash FROM audit_log ORDER BY rowid")
        return [r["audit_hash"] for r in rows]
    finally:
        os.unlink(path)


def test_audit_hash_chain_is_reproducible_across_runs():
    # Two independent runs of the SAME logical event sequence (different wall-clock
    # instants) must produce an IDENTICAL audit_hash chain.
    assert _chain_for_run() == _chain_for_run()


def test_audit_hash_chain_distinguishes_different_actions():
    # Sanity: the hash still reflects logical content (so it isn't trivially equal).
    chain = _chain_for_run()
    assert len(set(chain)) == len(chain)  # each distinct logical event -> distinct hash
