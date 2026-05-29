//! SQLite-backed append-only event storage — Rust port of
//! `EventBusStorage` (pi_event_fabric/bus/core.py), using `rusqlite` so the SQL
//! semantics (AUTOINCREMENT, UNIQUE, ORDER BY) are byte-for-byte identical.
//!
//! The clock is injected via [`Marker`] (timestamp + ordering_key + created_at)
//! rather than read from the wall clock, making the bus genuinely deterministic.

use crate::canonical::dumps_canonical;
use crate::event::{payload_hash, sha256_hex, DomainEvent, EventHeader};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};
use std::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    global_offset INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    partition_key TEXT NOT NULL,
    partition_offset INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    ordering_key TEXT NOT NULL,
    author_tenant_id TEXT NOT NULL,
    author_actor_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(partition_key, partition_offset)
);
CREATE INDEX IF NOT EXISTS idx_events_partition ON events(partition_key, partition_offset);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(author_tenant_id, partition_key);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, partition_key);
CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation_id);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    consumer_id TEXT NOT NULL,
    partition_key TEXT NOT NULL,
    last_consumed_offset INTEGER NOT NULL,
    last_event_id TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL,
    checkpointed_at TEXT NOT NULL,
    UNIQUE(consumer_id, partition_key)
);

CREATE TABLE IF NOT EXISTS epoch_markers (
    epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_number INTEGER NOT NULL UNIQUE,
    established_at TEXT NOT NULL,
    ordering_key TEXT NOT NULL,
    established_by TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS event_partitions (
    partition_key TEXT PRIMARY KEY,
    current_offset INTEGER NOT NULL DEFAULT 0,
    last_event_id TEXT NOT NULL DEFAULT '',
    last_event_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"#;

/// Injected clock output for a single append (the determinism fix).
/// `timestamp` is `canonical_timestamp(wall_time)`, `created_at` is used only
/// when a partition is first created (Python uses `datetime.now()` there).
#[derive(Clone, Debug)]
pub struct Marker {
    pub timestamp: String,
    pub ordering_key: String,
    pub created_at: String,
}

/// Deterministic consumer checkpoint (hash-verified), mirroring Python.
#[derive(Clone, Debug)]
pub struct ConsumerCheckpoint {
    pub consumer_id: String,
    pub partition_key: String,
    pub last_consumed_offset: i64,
    pub last_event_id: String,
    pub checkpoint_hash: String,
    pub checkpointed_at: String,
}

impl ConsumerCheckpoint {
    pub fn compute_hash(&self) -> String {
        // Deterministic: covers the consumer's logical position only. checkpointed_at
        // (wall-clock) is stored metadata but excluded from the hash.
        let mut m = Map::new();
        m.insert("consumer_id".into(), json!(self.consumer_id));
        m.insert("partition_key".into(), json!(self.partition_key));
        m.insert("last_consumed_offset".into(), json!(self.last_consumed_offset));
        m.insert("last_event_id".into(), json!(self.last_event_id));
        sha256_hex(&dumps_canonical(&Value::Object(m)))
    }
    pub fn to_value(&self) -> Value {
        json!({
            "consumer_id": self.consumer_id,
            "partition_key": self.partition_key,
            "last_consumed_offset": self.last_consumed_offset,
            "last_event_id": self.last_event_id,
            "checkpoint_hash": self.checkpoint_hash,
            "checkpointed_at": self.checkpointed_at,
        })
    }
}

type R<T> = Result<T, String>;
fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

pub struct EventBusStorage {
    conn: Mutex<Connection>,
}

impl EventBusStorage {
    pub fn open(db_path: &str) -> R<Self> {
        let conn = Connection::open(db_path).map_err(e)?;
        conn.execute_batch(SCHEMA).map_err(e)?;
        Ok(EventBusStorage { conn: Mutex::new(conn) })
    }

    /// Append one event to a partition. Deterministic given `marker`.
    pub fn append(
        &self,
        event_type: &str,
        partition_key: &str,
        payload: &Value,
        tenant_id: &str,
        actor_id: &str,
        correlation_id: &str,
        marker: &Marker,
    ) -> R<DomainEvent> {
        let payload_json = dumps_canonical(payload);
        let p_hash = payload_hash(payload);

        let mut conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let tx = conn.transaction().map_err(e)?;

        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT current_offset, last_event_hash FROM event_partitions WHERE partition_key = ?1",
                params![partition_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();

        let (current_offset, last_event_hash) = match existing {
            Some((off, h)) => (off, h),
            None => {
                tx.execute(
                    "INSERT INTO event_partitions (partition_key, current_offset, last_event_id, last_event_hash, created_at) VALUES (?1, 0, '', '', ?2)",
                    params![partition_key, marker.created_at],
                )
                .map_err(e)?;
                (0, String::new())
            }
        };

        let new_offset = current_offset + 1;
        // Deterministic id: (tenant, partition, offset) is already unique, so the
        // wall-clock ordering_key suffix is dropped to keep ids reproducible.
        let event_id = format!("evt_{tenant_id}_{partition_key}_{new_offset}");

        let header = EventHeader {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            partition_key: partition_key.to_string(),
            partition_offset: new_offset,
            timestamp: marker.timestamp.clone(),
            ordering_key: marker.ordering_key.clone(),
            author_tenant_id: tenant_id.to_string(),
            author_actor_id: actor_id.to_string(),
            correlation_id: correlation_id.to_string(),
            previous_event_hash: last_event_hash,
            payload_hash: p_hash,
        };
        let event = DomainEvent::new(header, payload.clone());

        tx.execute(
            "INSERT INTO events (event_id, event_type, partition_key, partition_offset, timestamp, ordering_key, author_tenant_id, author_actor_id, correlation_id, previous_event_hash, payload_hash, event_hash, payload_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                event.header.event_id, event.header.event_type, event.header.partition_key,
                event.header.partition_offset, event.header.timestamp, event.header.ordering_key,
                event.header.author_tenant_id, event.header.author_actor_id,
                event.header.correlation_id, event.header.previous_event_hash,
                event.header.payload_hash, event.event_hash, payload_json
            ],
        )
        .map_err(e)?;

        tx.execute(
            "UPDATE event_partitions SET current_offset = ?1, last_event_id = ?2, last_event_hash = ?3 WHERE partition_key = ?4",
            params![new_offset, event_id, event.event_hash, partition_key],
        )
        .map_err(e)?;

        tx.commit().map_err(e)?;
        Ok(event)
    }

    fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<DomainEvent> {
        let payload_json: String = row.get("payload_json")?;
        let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
        let header = EventHeader {
            event_id: row.get("event_id")?,
            event_type: row.get("event_type")?,
            partition_key: row.get("partition_key")?,
            partition_offset: row.get("partition_offset")?,
            timestamp: row.get("timestamp")?,
            ordering_key: row.get("ordering_key")?,
            author_tenant_id: row.get("author_tenant_id")?,
            author_actor_id: row.get("author_actor_id")?,
            correlation_id: row.get("correlation_id")?,
            previous_event_hash: row.get("previous_event_hash")?,
            payload_hash: row.get("payload_hash")?,
        };
        let event_hash: String = row.get("event_hash")?;
        Ok(DomainEvent { header, payload, event_hash })
    }

    pub fn read_partition(
        &self,
        partition_key: &str,
        start_offset: i64,
        limit: i64,
        tenant_filter: Option<&str>,
    ) -> R<Vec<DomainEvent>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let (sql, want_tenant) = match tenant_filter {
            Some(_) => (
                "SELECT * FROM events WHERE partition_key = ?1 AND partition_offset >= ?2 AND author_tenant_id = ?3 ORDER BY partition_offset ASC LIMIT ?4",
                true,
            ),
            None => (
                "SELECT * FROM events WHERE partition_key = ?1 AND partition_offset >= ?2 ORDER BY partition_offset ASC LIMIT ?3",
                false,
            ),
        };
        let mut stmt = conn.prepare(sql).map_err(e)?;
        let rows = if want_tenant {
            stmt.query_map(
                params![partition_key, start_offset, tenant_filter.unwrap(), limit],
                Self::row_to_event,
            )
        } else {
            stmt.query_map(params![partition_key, start_offset, limit], Self::row_to_event)
        }
        .map_err(e)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(e)
    }

    pub fn read_event(&self, event_id: &str) -> R<Option<DomainEvent>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let mut stmt = conn.prepare("SELECT * FROM events WHERE event_id = ?1").map_err(e)?;
        let mut rows = stmt.query_map(params![event_id], Self::row_to_event).map_err(e)?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(e)?)),
            None => Ok(None),
        }
    }

    pub fn read_by_correlation(&self, correlation_id: &str) -> R<Vec<DomainEvent>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let mut stmt = conn
            .prepare("SELECT * FROM events WHERE correlation_id = ?1 ORDER BY global_offset ASC")
            .map_err(e)?;
        let rows = stmt.query_map(params![correlation_id], Self::row_to_event).map_err(e)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(e)
    }

    pub fn get_partition_tail(&self, partition_key: &str, n: i64) -> R<Vec<DomainEvent>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let mut stmt = conn
            .prepare("SELECT * FROM events WHERE partition_key = ?1 ORDER BY partition_offset DESC LIMIT ?2")
            .map_err(e)?;
        let rows = stmt.query_map(params![partition_key, n], Self::row_to_event).map_err(e)?;
        let mut v = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(e)?;
        v.reverse(); // Python returns [...][::-1]
        Ok(v)
    }

    pub fn get_partition_metadata(&self, partition_key: &str) -> R<Option<Value>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let mut stmt = conn
            .prepare("SELECT partition_key, current_offset, last_event_id, last_event_hash, created_at FROM event_partitions WHERE partition_key = ?1")
            .map_err(e)?;
        let mut rows = stmt
            .query_map(params![partition_key], |r| {
                Ok(json!({
                    "partition_key": r.get::<_, String>(0)?,
                    "current_offset": r.get::<_, i64>(1)?,
                    "last_event_id": r.get::<_, String>(2)?,
                    "last_event_hash": r.get::<_, String>(3)?,
                    "created_at": r.get::<_, String>(4)?,
                }))
            })
            .map_err(e)?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(e)?)),
            None => Ok(None),
        }
    }

    pub fn write_checkpoint(&self, cp: &ConsumerCheckpoint) -> R<()> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        conn.execute(
            "INSERT INTO checkpoints (consumer_id, partition_key, last_consumed_offset, last_event_id, checkpoint_hash, checkpointed_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(consumer_id, partition_key) DO UPDATE SET last_consumed_offset=excluded.last_consumed_offset, last_event_id=excluded.last_event_id, checkpoint_hash=excluded.checkpoint_hash, checkpointed_at=excluded.checkpointed_at",
            params![cp.consumer_id, cp.partition_key, cp.last_consumed_offset, cp.last_event_id, cp.checkpoint_hash, cp.checkpointed_at],
        ).map_err(e)?;
        Ok(())
    }

    pub fn read_checkpoint(&self, consumer_id: &str, partition_key: &str) -> R<Option<ConsumerCheckpoint>> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let mut stmt = conn
            .prepare("SELECT consumer_id, partition_key, last_consumed_offset, last_event_id, checkpoint_hash, checkpointed_at FROM checkpoints WHERE consumer_id = ?1 AND partition_key = ?2")
            .map_err(e)?;
        let mut rows = stmt
            .query_map(params![consumer_id, partition_key], |r| {
                Ok(ConsumerCheckpoint {
                    consumer_id: r.get(0)?,
                    partition_key: r.get(1)?,
                    last_consumed_offset: r.get(2)?,
                    last_event_id: r.get(3)?,
                    checkpoint_hash: r.get(4)?,
                    checkpointed_at: r.get(5)?,
                })
            })
            .map_err(e)?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(e)?)),
            None => Ok(None),
        }
    }

    /// Mirrors `verify_partition_chain` -> (ok, errors).
    pub fn verify_partition_chain(&self, partition_key: &str) -> R<(bool, Vec<String>)> {
        let events = self.read_partition(partition_key, 1, 1_000_000, None)?;
        if events.is_empty() {
            return Ok((true, vec![]));
        }
        let mut errors = Vec::new();
        for (i, ev) in events.iter().enumerate() {
            let expected = &ev.event_hash;
            // Recompute every event including the genesis (i == 0); possible now that
            // the hash is content-addressed (wall-clock-free), closing the prior hole
            // where a tampered first-event payload still passed verification.
            let recomputed = DomainEvent::compute_hash(&ev.header, &ev.payload);
            if expected != &recomputed {
                errors.push(format!(
                    "hash_mismatch at offset {}: expected={expected}, got={recomputed}",
                    ev.header.partition_offset
                ));
            }
            if i > 0 {
                let prev_hash = &events[i - 1].event_hash;
                if &ev.header.previous_event_hash != prev_hash {
                    errors.push(format!(
                        "chain_break at offset {}: expected_prev={prev_hash}, got={}",
                        ev.header.partition_offset, ev.header.previous_event_hash
                    ));
                }
            }
        }
        Ok((errors.is_empty(), errors))
    }

    pub fn get_stats(&self) -> R<Value> {
        let conn = self.conn.lock().map_err(|_| "poisoned".to_string())?;
        let count = |sql: &str| -> rusqlite::Result<i64> { conn.query_row(sql, [], |r| r.get(0)) };
        Ok(json!({
            "event_count": count("SELECT COUNT(*) FROM events").map_err(e)?,
            "partition_count": count("SELECT COUNT(*) FROM event_partitions").map_err(e)?,
            "checkpoint_count": count("SELECT COUNT(*) FROM checkpoints").map_err(e)?,
            "epoch_count": count("SELECT COUNT(*) FROM epoch_markers").unwrap_or(0),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(ts: &str, seq: u64) -> Marker {
        let ordering_key = format!("{ts}:{seq:012}:eventbus");
        Marker { timestamp: ts.to_string(), ordering_key, created_at: "2026-01-01T00:00:00+00:00".into() }
    }

    #[test]
    fn append_chains_and_verifies() {
        let st = EventBusStorage::open(":memory:").unwrap();
        let e1 = st.append("artifact:created", "default", &json!({"x":1}), "t1", "a1", "c1",
            &marker("2026-01-01T00:00:00.000000Z", 1)).unwrap();
        let e2 = st.append("artifact:created", "default", &json!({"x":2}), "t1", "a1", "c1",
            &marker("2026-01-01T00:00:01.000000Z", 1)).unwrap();
        assert_eq!(e1.header.partition_offset, 1);
        assert_eq!(e2.header.partition_offset, 2);
        assert_eq!(e2.header.previous_event_hash, e1.event_hash); // chained
        let (ok, errs) = st.verify_partition_chain("default").unwrap();
        assert!(ok, "{errs:?}");
        let got = st.read_partition("default", 1, 100, None).unwrap();
        assert_eq!(got.len(), 2);
    }
}
