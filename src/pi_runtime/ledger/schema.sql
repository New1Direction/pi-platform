-- PI Agents Analysis Squad - Immutable Event Ledger Schema
-- Enforces strict append-only behavior at the DATABASE level (not just Python)

CREATE TABLE IF NOT EXISTS ledger_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         TEXT NOT NULL UNIQUE,
    actor_id        TEXT NOT NULL,
    from_state      TEXT NOT NULL,
    to_state        TEXT NOT NULL,
    evidence_hash   TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    provenance      TEXT NOT NULL,           -- JSON array of UUIDs
    entropy_delta   INTEGER NOT NULL,
    inserted_at     TEXT DEFAULT (datetime('now')),
    CHECK (evidence_hash GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]')  -- 64 hex chars
);

-- === APPEND-ONLY ENFORCEMENT (Critical Governance Layer) ===
-- These triggers make it impossible to modify or delete history at the DB level.

CREATE TRIGGER IF NOT EXISTS prevent_update
    BEFORE UPDATE ON ledger_entries
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'UPDATE operations are forbidden - ledger is strictly append-only. Violates PI-RUNTIME-SPEC v1.4.0 determinism.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_delete
    BEFORE DELETE ON ledger_entries
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'DELETE operations are forbidden - ledger is strictly append-only. Violates deterministic provenance.');
END;

-- Optional: Index for fast lookup by task_id and state transitions
CREATE INDEX IF NOT EXISTS idx_ledger_task_id ON ledger_entries(task_id);
CREATE INDEX IF NOT EXISTS idx_ledger_state ON ledger_entries(from_state, to_state);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger_entries(timestamp);
