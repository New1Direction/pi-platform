//! PI Platform deterministic micro-agent core (Rust port).
//!
//! Each agent is a pure function over a typed (serde) input that returns a
//! typed output, mirroring the original Python `BaseModel` in/out contract.
//! Agents are reachable by name through [`registry::run_agent`], which is what
//! the PyO3 layer (`pi-py`) exposes to Python.

pub mod agents;
pub mod pyutil;
pub mod registry;

pub use registry::{list_agents, run_agent, run_agent_safe};
