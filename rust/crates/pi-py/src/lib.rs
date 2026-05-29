//! PyO3 bindings: expose the Rust agent core to Python as `pi_core`.
//!
//! Python imports this native module and calls agents by their original class
//! name, passing/receiving JSON — so the existing orchestration layer migrates
//! without touching its call sites.

use pyo3::prelude::*;

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

#[pymodule]
fn pi_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_agent, m)?)?;
    m.add_function(wrap_pyfunction!(list_agents, m)?)?;
    m.add("__doc__", "PI Platform deterministic agent core (Rust/PyO3).")?;
    Ok(())
}
