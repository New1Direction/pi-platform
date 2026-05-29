//! Deterministic fail-closed gates from `pi_agent_chain/governance/`:
//! the SchemaGate (worker-output structural validation) and TransitionGate
//! (finite-state-machine enforcement). Both return either "valid" or a
//! GovernanceViolation. The violation's `violation_id` (uuid) and `detected_at`
//! (utcnow) are non-deterministic and excluded from parity; the
//! rule/severity/context/action are deterministic and compared byte-for-byte.

use serde_json::{json, Value};

fn py_type_name(v: &Value) -> &'static str {
    match v {
        Value::Object(_) => "dict",
        Value::Array(_) => "list",
        Value::String(_) => "str",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::Null => "NoneType",
    }
}

fn violation(rule: &str, worker_id: &str, root_goal_id: &str, severity: &str, context: Value) -> Value {
    json!({
        "rule": rule, "worker_id": worker_id, "root_goal_id": root_goal_id,
        "severity": severity, "context": context, "action_taken": "HALT",
    })
}

/// The 6 canonical worker-output schemas (all identical shape).
fn is_known_worker(worker_id: &str) -> bool {
    matches!(
        worker_id,
        "acquisition_gateway" | "structural_extractor" | "semantic_typer"
            | "flow_mapper" | "spec_synthesizer" | "verifier"
    )
}

/// Mirrors `SchemaGate.validate`. Returns `Value::Null` if valid, else a
/// violation. `payload` is the worker output object (must have payload+type).
pub fn schema_gate(worker_id: &str, payload: &Value, root_goal_id: &str) -> Value {
    if !is_known_worker(worker_id) {
        return Value::Null; // unregistered worker = unrestricted
    }
    let obj = match payload.as_object() {
        Some(o) => o,
        None => return Value::Null, // Python would treat non-dict payload upstream
    };

    // required: payload, type
    for key in ["payload", "type"] {
        if !obj.contains_key(key) {
            let payload_keys: Vec<&String> = obj.keys().collect();
            return violation(
                "INVALID_OUTPUT", worker_id, root_goal_id, "ERROR",
                json!({"field": key, "reason": format!("Missing required field '{key}'"),
                       "payload_keys": payload_keys}),
            );
        }
    }

    // type checks for the two declared properties (payload: object, type: string)
    // Python iterates payload.items() (insertion order); preserve_order matches it.
    for (key, value) in obj {
        let expected = match key.as_str() {
            "payload" => "object",
            "type" => "string",
            _ => continue,
        };
        let ok = match expected {
            "object" => value.is_object(),
            "string" => value.is_string(),
            _ => true,
        };
        if !ok {
            let label = if expected == "object" { "object" } else { "string" };
            let payload_keys: Vec<&String> = obj.keys().collect();
            return violation(
                "INVALID_OUTPUT", worker_id, root_goal_id, "ERROR",
                json!({"field": key,
                       "reason": format!("Expected {label}, got {}", py_type_name(value)),
                       "payload_keys": payload_keys}),
            );
        }
    }
    Value::Null
}

// ── Transition gate ─────────────────────────────────────────────────────────

struct Rule {
    from: &'static str,
    to: &'static str,
    required_status: &'static str,
}

/// CANONICAL_TRANSITIONS (max_depth=3, max_branch_count=8 for all).
fn canonical_rules() -> Vec<Rule> {
    let linear = [
        ("REGISTERED", "SCOPED"), ("SCOPED", "CAPTURE_READY"),
        ("CAPTURE_READY", "CAPTURING"), ("CAPTURING", "NORMALIZING"),
        ("NORMALIZING", "EXTRACTING"), ("EXTRACTING", "ASSEMBLING_IR"),
        ("ASSEMBLING_IR", "GENERATING_SPEC"), ("GENERATING_SPEC", "COMPLETED"),
    ];
    let fail_from = [
        "REGISTERED", "SCOPED", "CAPTURE_READY", "CAPTURING", "NORMALIZING",
        "EXTRACTING", "VERIFYING", "ASSEMBLING_IR", "GENERATING_SPEC",
    ];
    let mut rules: Vec<Rule> = linear
        .iter()
        .map(|(f, t)| Rule { from: f, to: t, required_status: "SUCCESS" })
        .collect();
    for f in fail_from {
        rules.push(Rule { from: f, to: "FAILED", required_status: "FAILURE" });
    }
    rules.push(Rule { from: "FAILED", to: "RETRY_PENDING", required_status: "RETRYABLE_FAILURE" });
    rules.push(Rule { from: "EXTRACTING", to: "INVALID_EVIDENCE", required_status: "INSUFFICIENT_EVIDENCE" });
    rules.push(Rule { from: "VERIFYING", to: "INVALID_EVIDENCE", required_status: "VERIFICATION_MISMATCH" });
    rules
}

const MAX_DEPTH: i64 = 3;
const MAX_BRANCH: i64 = 8;

/// Mirrors `TransitionGate.validate`. Returns Null if valid, else a violation.
pub fn transition_gate(
    current: &str,
    proposed: &str,
    status: &str,
    worker_id: &str,
    root_goal_id: &str,
    depth: i64,
    branch_count: i64,
) -> Value {
    let rules = canonical_rules();
    // `_index = {(from,to): r}` — last rule wins on duplicate keys (Python dict).
    let rule = rules.iter().rev().find(|r| r.from == current && r.to == proposed);

    let rule = match rule {
        None => {
            return violation(
                "TRANSITION_NOT_ALLOWED", worker_id, root_goal_id, "CRITICAL",
                json!({"from_state": current, "proposed_state": proposed,
                       "reason": "No rule authorizes this transition"}),
            );
        }
        Some(r) => r,
    };

    // status check (the Python inner "FAILURE/FAILURE" branch is unreachable dead code)
    if status != rule.required_status {
        return violation(
            "STATUS_MISMATCH", worker_id, root_goal_id, "ERROR",
            json!({"required_status": rule.required_status, "actual_status": status}),
        );
    }
    if depth >= MAX_DEPTH {
        return violation(
            "MAX_DEPTH_EXCEEDED", worker_id, root_goal_id, "CRITICAL",
            json!({"depth": depth, "max_depth": MAX_DEPTH}),
        );
    }
    if branch_count >= MAX_BRANCH {
        return violation(
            "BRANCH_OVERFLOW", worker_id, root_goal_id, "CRITICAL",
            json!({"branch_count": branch_count, "max_branch_count": MAX_BRANCH}),
        );
    }
    Value::Null
}

pub fn dispatch(op: &str, args: &Value) -> Result<Value, String> {
    match op {
        "schema_gate" => Ok(schema_gate(
            args["worker_id"].as_str().unwrap_or(""),
            &args["payload"],
            args["root_goal_id"].as_str().unwrap_or(""),
        )),
        "transition_gate" => Ok(transition_gate(
            args["current_state"].as_str().unwrap_or(""),
            args["proposed_state"].as_str().unwrap_or(""),
            args["status"].as_str().unwrap_or("SUCCESS"),
            args["worker_id"].as_str().unwrap_or(""),
            args["root_goal_id"].as_str().unwrap_or(""),
            args.get("depth").and_then(|v| v.as_i64()).unwrap_or(0),
            args.get("branch_count").and_then(|v| v.as_i64()).unwrap_or(0),
        )),
        _ => Err(format!("unknown gate op: {op}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_gate_missing_field() {
        let v = schema_gate("verifier", &json!({"type": "X"}), "g1");
        assert_eq!(v["rule"], json!("INVALID_OUTPUT"));
        assert_eq!(v["context"]["field"], json!("payload"));
    }

    #[test]
    fn schema_gate_valid() {
        let v = schema_gate("verifier", &json!({"payload": {}, "type": "X"}), "g1");
        assert!(v.is_null());
    }

    #[test]
    fn transition_ok_and_bad() {
        assert!(transition_gate("REGISTERED", "SCOPED", "SUCCESS", "w", "g", 0, 0).is_null());
        let v = transition_gate("REGISTERED", "COMPLETED", "SUCCESS", "w", "g", 0, 0);
        assert_eq!(v["rule"], json!("TRANSITION_NOT_ALLOWED"));
    }
}
