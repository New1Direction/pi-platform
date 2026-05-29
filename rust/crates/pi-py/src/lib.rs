//! PyO3 bindings: expose the Rust agent core to Python as `pi_core`.
//!
//! Python imports this native module and calls agents by their original class
//! name, passing/receiving JSON — so the existing orchestration layer migrates
//! without touching its call sites.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pi_event_fabric::{ConsumerCheckpoint, EventBusStorage, Marker};

/// Deterministic event bus (Rust port of pi_event_fabric.bus.core), exposed to
/// the parity harness. JSON in/out; the clock is injected (timestamp /
/// ordering_key / created_at) so runs are reproducible.
#[pyclass]
struct EventBus {
    inner: EventBusStorage,
}

#[pymethods]
impl EventBus {
    #[new]
    fn new(db_path: &str) -> PyResult<Self> {
        EventBusStorage::open(db_path)
            .map(|inner| EventBus { inner })
            .map_err(PyValueError::new_err)
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &self,
        event_type: &str,
        partition_key: &str,
        payload_json: &str,
        tenant_id: &str,
        actor_id: &str,
        correlation_id: &str,
        timestamp: &str,
        ordering_key: &str,
        created_at: &str,
    ) -> PyResult<String> {
        let payload: serde_json::Value =
            serde_json::from_str(payload_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let marker = Marker {
            timestamp: timestamp.to_string(),
            ordering_key: ordering_key.to_string(),
            created_at: created_at.to_string(),
        };
        let ev = self
            .inner
            .append(event_type, partition_key, &payload, tenant_id, actor_id, correlation_id, &marker)
            .map_err(PyValueError::new_err)?;
        Ok(ev.to_value().to_string())
    }

    #[pyo3(signature = (partition_key, start_offset=1, limit=1000, tenant_filter=None))]
    fn read_partition(
        &self,
        partition_key: &str,
        start_offset: i64,
        limit: i64,
        tenant_filter: Option<String>,
    ) -> PyResult<String> {
        let evs = self
            .inner
            .read_partition(partition_key, start_offset, limit, tenant_filter.as_deref())
            .map_err(PyValueError::new_err)?;
        let arr: Vec<serde_json::Value> = evs.iter().map(|e| e.to_value()).collect();
        Ok(serde_json::Value::Array(arr).to_string())
    }

    fn read_event(&self, event_id: &str) -> PyResult<Option<String>> {
        let ev = self.inner.read_event(event_id).map_err(PyValueError::new_err)?;
        Ok(ev.map(|e| e.to_value().to_string()))
    }

    fn read_by_correlation(&self, correlation_id: &str) -> PyResult<String> {
        let evs = self.inner.read_by_correlation(correlation_id).map_err(PyValueError::new_err)?;
        let arr: Vec<serde_json::Value> = evs.iter().map(|e| e.to_value()).collect();
        Ok(serde_json::Value::Array(arr).to_string())
    }

    fn get_partition_tail(&self, partition_key: &str, n: i64) -> PyResult<String> {
        let evs = self.inner.get_partition_tail(partition_key, n).map_err(PyValueError::new_err)?;
        let arr: Vec<serde_json::Value> = evs.iter().map(|e| e.to_value()).collect();
        Ok(serde_json::Value::Array(arr).to_string())
    }

    fn get_partition_metadata(&self, partition_key: &str) -> PyResult<Option<String>> {
        let m = self.inner.get_partition_metadata(partition_key).map_err(PyValueError::new_err)?;
        Ok(m.map(|v| v.to_string()))
    }

    fn verify_partition_chain(&self, partition_key: &str) -> PyResult<String> {
        let (ok, errors) = self.inner.verify_partition_chain(partition_key).map_err(PyValueError::new_err)?;
        Ok(serde_json::json!({"ok": ok, "errors": errors}).to_string())
    }

    fn get_stats(&self) -> PyResult<String> {
        Ok(self.inner.get_stats().map_err(PyValueError::new_err)?.to_string())
    }

    fn write_checkpoint(
        &self,
        consumer_id: &str,
        partition_key: &str,
        last_consumed_offset: i64,
        last_event_id: &str,
        checkpointed_at: &str,
    ) -> PyResult<String> {
        let mut cp = ConsumerCheckpoint {
            consumer_id: consumer_id.to_string(),
            partition_key: partition_key.to_string(),
            last_consumed_offset,
            last_event_id: last_event_id.to_string(),
            checkpoint_hash: String::new(),
            checkpointed_at: checkpointed_at.to_string(),
        };
        cp.checkpoint_hash = cp.compute_hash();
        self.inner.write_checkpoint(&cp).map_err(PyValueError::new_err)?;
        Ok(cp.to_value().to_string())
    }

    fn read_checkpoint(&self, consumer_id: &str, partition_key: &str) -> PyResult<Option<String>> {
        let cp = self.inner.read_checkpoint(consumer_id, partition_key).map_err(PyValueError::new_err)?;
        Ok(cp.map(|c| c.to_value().to_string()))
    }
}

/// Run an agent by its (original Python) class name.
///
/// `input_json` is the serialized input model; the return value is the
/// serialized output model. Raises `ValueError` on unknown agent or bad input.
#[pyfunction]
fn run_agent(name: &str, input_json: &str) -> PyResult<String> {
    pi_agents::run_agent(name, input_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Every agent name currently available in the Rust core.
#[pyfunction]
fn list_agents() -> Vec<String> {
    pi_agents::list_agents()
}

fn json_dispatch(
    f: fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
    op: &str,
    args_json: &str,
) -> PyResult<String> {
    let args: serde_json::Value =
        serde_json::from_str(args_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let out = f(op, &args).map_err(PyValueError::new_err)?;
    Ok(out.to_string())
}

/// Deterministic schema-evolution ops (fingerprint / validate / find_path / migrate_data).
#[pyfunction]
fn schema_op(op: &str, args_json: &str) -> PyResult<String> {
    json_dispatch(pi_event_fabric::schema_evolution::dispatch, op, args_json)
}

/// Deterministic governance ops (rule_hash / compiled_hash / evaluate).
#[pyfunction]
fn governance_op(op: &str, args_json: &str) -> PyResult<String> {
    json_dispatch(pi_event_fabric::governance_compiler::dispatch, op, args_json)
}

#[pymodule]
fn pi_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_agent, m)?)?;
    m.add_function(wrap_pyfunction!(list_agents, m)?)?;
    m.add_function(wrap_pyfunction!(schema_op, m)?)?;
    m.add_function(wrap_pyfunction!(governance_op, m)?)?;
    m.add_class::<EventBus>()?;
    m.add("__doc__", "PI Platform deterministic agent core (Rust/PyO3).")?;
    Ok(())
}
