//! Deterministic append-only event bus — Rust port of
//! `pi_event_fabric/bus/core.py`.
//!
//! Faithful to the Python original's cryptographic event chaining and SQLite
//! storage semantics, with one deliberate fix: the clock is **injectable**.
//! The Python `DeterministicClock` actually reads wall-clock time (its name
//! notwithstanding), so identical inputs hash differently across runs. Here the
//! caller supplies the ordering marker, making the bus genuinely deterministic;
//! the parity harness feeds Python and Rust the same markers to prove
//! byte-identical hashing/chaining.

pub mod canonical;
pub mod event;
pub mod storage;

pub use canonical::dumps_canonical;
pub use event::{payload_hash, DomainEvent, EventHeader};
pub use storage::{ConsumerCheckpoint, EventBusStorage, Marker};
