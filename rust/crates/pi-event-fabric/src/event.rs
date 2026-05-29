//! Event model + cryptographic hashing, mirroring
//! `pi_event_fabric/bus/core.py` (EventHeader / DomainEvent).

use crate::canonical::dumps_canonical;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Immutable event header (11 fields), serialized for hashing in the exact
/// field set and types the Python `EventHeader.serialize()` produces.
#[derive(Clone, Debug, PartialEq)]
pub struct EventHeader {
    pub event_id: String,
    pub event_type: String, // the EventType `.value` string
    pub partition_key: String,
    pub partition_offset: i64,
    pub timestamp: String,
    pub ordering_key: String,
    pub author_tenant_id: String,
    pub author_actor_id: String,
    pub correlation_id: String,
    pub previous_event_hash: String,
    pub payload_hash: String,
}

impl EventHeader {
    /// Equivalent of Python `EventHeader.serialize()` — the FULL header dict used
    /// for storage/serialization (and full-record parity comparison).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("event_id".into(), json!(self.event_id));
        m.insert("event_type".into(), json!(self.event_type));
        m.insert("partition_key".into(), json!(self.partition_key));
        m.insert("partition_offset".into(), json!(self.partition_offset));
        m.insert("timestamp".into(), json!(self.timestamp));
        m.insert("ordering_key".into(), json!(self.ordering_key));
        m.insert("author_tenant_id".into(), json!(self.author_tenant_id));
        m.insert("author_actor_id".into(), json!(self.author_actor_id));
        m.insert("correlation_id".into(), json!(self.correlation_id));
        m.insert("previous_event_hash".into(), json!(self.previous_event_hash));
        m.insert("payload_hash".into(), json!(self.payload_hash));
        Value::Object(m)
    }

    /// Content-addressed identity dict used for the event hash. Mirrors the Python
    /// `DomainEvent._compute_hash`: covers the logical event + causal position but
    /// DELIBERATELY excludes the wall-clock fields (timestamp, ordering_key) and the
    /// event_id (which embeds the ordering_key), so the same logical event hashes
    /// identically across runs — genuine deterministic replay.
    pub fn identity_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("event_type".into(), json!(self.event_type));
        m.insert("partition_key".into(), json!(self.partition_key));
        m.insert("partition_offset".into(), json!(self.partition_offset));
        m.insert("author_tenant_id".into(), json!(self.author_tenant_id));
        m.insert("author_actor_id".into(), json!(self.author_actor_id));
        m.insert("correlation_id".into(), json!(self.correlation_id));
        m.insert("previous_event_hash".into(), json!(self.previous_event_hash));
        m.insert("payload_hash".into(), json!(self.payload_hash));
        Value::Object(m)
    }
}

/// Full event record. `event_hash = sha256(canonical(header) + canonical(payload))`.
#[derive(Clone, Debug)]
pub struct DomainEvent {
    pub header: EventHeader,
    pub payload: Value,
    pub event_hash: String,
}

impl DomainEvent {
    pub fn new(header: EventHeader, payload: Value) -> Self {
        let event_hash = Self::compute_hash(&header, &payload);
        DomainEvent { header, payload, event_hash }
    }

    /// Mirrors `DomainEvent._compute_hash`: content-addressed over the header
    /// IDENTITY (no wall-clock / event_id) + payload.
    pub fn compute_hash(header: &EventHeader, payload: &Value) -> String {
        let header_json = dumps_canonical(&header.identity_value());
        let payload_json = dumps_canonical(payload);
        sha256_hex(&format!("{header_json}{payload_json}"))
    }

    /// Full serialized record (header dict + payload + event_hash), used by the
    /// PyO3 bridge so the parity harness can compare entire events.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("header".into(), self.header.to_value());
        m.insert("payload".into(), self.payload.clone());
        m.insert("event_hash".into(), json!(self.event_hash));
        Value::Object(m)
    }
}

/// `payload_hash = sha256(canonical(payload))`.
pub fn payload_hash(payload: &Value) -> String {
    sha256_hex(&dumps_canonical(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_header(prev: &str, payload_hash: &str) -> EventHeader {
        EventHeader {
            event_id: "evt_t1_default_1_2026-01-01T00:00:00.000000Z:000000000001:eventbus".into(),
            event_type: "artifact:created".into(),
            partition_key: "default".into(),
            partition_offset: 1,
            timestamp: "2026-01-01T00:00:00.000000Z".into(),
            ordering_key: "2026-01-01T00:00:00.000000Z:000000000001:eventbus".into(),
            author_tenant_id: "t1".into(),
            author_actor_id: "a1".into(),
            correlation_id: "c1".into(),
            previous_event_hash: prev.into(),
            payload_hash: payload_hash.into(),
        }
    }

    #[test]
    fn hash_is_stable_and_payload_order_independent() {
        let p1 = json!({"b": 2, "a": 1});
        let p2 = json!({"a": 1, "b": 2});
        let ph = payload_hash(&p1);
        let e1 = DomainEvent::new(fixed_header("", &ph), p1);
        let e2 = DomainEvent::new(fixed_header("", &payload_hash(&p2)), p2);
        assert_eq!(e1.event_hash, e2.event_hash); // sort_keys => order-independent
        assert_eq!(e1.event_hash.len(), 64);
    }
}
