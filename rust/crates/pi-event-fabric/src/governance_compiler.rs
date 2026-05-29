//! Deterministic core of `pi_event_fabric/governance/compiler.py`:
//! rule hashing, static condition validation, the operator evaluator, and the
//! fail-closed priority decision engine. (The SQLite `GovernanceRegistry` CRUD
//! is persistence plumbing, scoped out of this parity port.)

use crate::canonical::dumps_canonical;
use crate::event::sha256_hex;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Clone)]
pub struct ConditionIn {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub value: Value,
}

#[derive(Deserialize, Clone)]
pub struct RuleIn {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub target_scope: String,
    pub conditions: Vec<ConditionIn>,
    pub effect: String,
    pub priority: i64,
    pub version: String,
    #[serde(default)]
    pub parent_rule_id: Option<String>,
}

const ALLOWED_FIELDS: &[&str] = &[
    "tenant_id", "actor_id", "role", "action", "resource_type", "resource_id",
    "composition_id", "snapshot_id", "worker_id", "stage", "event_type",
    "partition_key", "epoch_number", "schema_name", "schema_version",
    "connector_id", "connector_trust_tier", "sandbox_policy",
];

fn condition_to_value(c: &ConditionIn) -> Value {
    json!({"field": c.field, "operator": c.operator, "value": c.value})
}

/// Mirrors `PolicyCompiler._validate_condition`.
fn validate_condition(c: &ConditionIn) -> Result<(), String> {
    if !ALLOWED_FIELDS.contains(&c.field.as_str()) {
        return Err(format!("Field '{}' not in allowed fields", c.field));
    }
    if c.operator == "matches" {
        return Err("Regex matching is not allowed in the deterministic policy DSL".to_string());
    }
    Ok(())
}

/// Mirrors `GovernanceRule._compute_hash`.
pub fn rule_hash(r: &RuleIn) -> String {
    let canonical = json!({
        "rule_id": r.rule_id, "name": r.name, "description": r.description,
        "target_scope": r.target_scope,
        "conditions": r.conditions.iter().map(condition_to_value).collect::<Vec<_>>(),
        "effect": r.effect, "priority": r.priority, "version": r.version,
        "parent_rule_id": r.parent_rule_id,
    });
    sha256_hex(&dumps_canonical(&canonical))
}

/// Mirrors `PolicyCompiler.compile` -> compiled_hash.
fn compiled_hash(r: &RuleIn) -> String {
    let canonical = json!({
        "rule_id": r.rule_id,
        "conditions": r.conditions.iter().map(condition_to_value).collect::<Vec<_>>(),
        "effect": r.effect, "priority": r.priority,
    });
    sha256_hex(&dumps_canonical(&canonical))
}

/// Mirrors `PolicyCompiler._evaluate` for one condition. Python comparison
/// semantics: numbers numerically, strings lexicographically; ordered compares
/// between mismatched types raise in Python — callers use consistent types.
fn eval_condition(c: &ConditionIn, ctx: &Value) -> bool {
    let fv = ctx.get(&c.field).cloned().unwrap_or(Value::Null);
    let t = &c.value;
    match c.operator.as_str() {
        "eq" => &fv == t,
        "ne" => &fv != t,
        "gt" => num_or_str_cmp(&fv, t).map(|o| o.is_gt()).unwrap_or(false),
        "lt" => num_or_str_cmp(&fv, t).map(|o| o.is_lt()).unwrap_or(false),
        "contains" => match &fv {
            Value::String(s) => t.as_str().map(|ts| s.contains(ts)).unwrap_or(false),
            Value::Array(a) => a.contains(t),
            Value::Object(m) => t.as_str().map(|k| m.contains_key(k)).unwrap_or(false),
            _ => false,
        },
        "starts_with" => match (fv.as_str(), t.as_str()) {
            (Some(s), Some(p)) => s.starts_with(p),
            _ => false,
        },
        "ends_with" => match (fv.as_str(), t.as_str()) {
            (Some(s), Some(p)) => s.ends_with(p),
            _ => false,
        },
        "in" => t.as_array().map(|arr| arr.contains(&fv)).unwrap_or(false),
        "not_in" => t.as_array().map(|arr| !arr.contains(&fv)).unwrap_or(false),
        "exists" => ctx.get(&c.field).map(|v| !v.is_null()).unwrap_or(false),
        _ => false,
    }
}

fn num_or_str_cmp(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    if a.is_null() || b.is_null() {
        return None;
    }
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        return x.partial_cmp(&y);
    }
    if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
        return Some(x.cmp(y));
    }
    None
}

/// Mirrors `GovernanceEngine.evaluate` over compiled rules: stable sort by
/// priority, AND-of-conditions per rule, DENY terminal, fail-closed.
pub fn evaluate(rules: &[RuleIn], ctx: &Value) -> Result<Value, String> {
    for r in rules {
        for c in &r.conditions {
            validate_condition(c)?;
        }
    }
    // stable sort by priority (lower first) — matches Python list.sort stability
    let mut order: Vec<usize> = (0..rules.len()).collect();
    order.sort_by_key(|&i| rules[i].priority);

    let mut matched: Vec<String> = Vec::new();
    let mut denied_by: Option<String> = None;
    let mut final_effect = "deny".to_string();

    for &i in &order {
        let r = &rules[i];
        let all = r.conditions.iter().all(|c| eval_condition(c, ctx));
        if all {
            matched.push(r.rule_id.clone());
            match r.effect.as_str() {
                "deny" => {
                    denied_by = Some(r.rule_id.clone());
                    final_effect = "deny".to_string();
                    break;
                }
                "allow" => final_effect = "allow".to_string(),
                "require_approval" => final_effect = "require_approval".to_string(),
                _ => {}
            }
        }
    }
    if matched.is_empty() {
        final_effect = "deny".to_string();
    }

    let context_id = ctx.get("correlation_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let evaluated_at = ctx.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let decision_data = json!({
        "context_id": context_id, "effect": final_effect,
        "matched_rules": matched, "denied_by": denied_by,
    });
    let decision_hash = sha256_hex(&dumps_canonical(&decision_data));

    Ok(json!({
        "decision_id": format!("dec_{context_id}_{}", &decision_hash[..16]),
        "context_id": context_id,
        "effect": final_effect,
        "matched_rules": matched,
        "denied_by": denied_by,
        "decision_hash": decision_hash,
        "evaluated_at": evaluated_at,
    }))
}

pub fn dispatch(op: &str, args: &Value) -> Result<Value, String> {
    match op {
        "rule_hash" => {
            let r: RuleIn = serde_json::from_value(args["rule"].clone()).map_err(|e| e.to_string())?;
            Ok(json!(rule_hash(&r)))
        }
        "compiled_hash" => {
            let r: RuleIn = serde_json::from_value(args["rule"].clone()).map_err(|e| e.to_string())?;
            for c in &r.conditions {
                validate_condition(c)?;
            }
            Ok(json!(compiled_hash(&r)))
        }
        "evaluate" => {
            let rules: Vec<RuleIn> = serde_json::from_value(args["rules"].clone()).map_err(|e| e.to_string())?;
            evaluate(&rules, &args["context"])
        }
        _ => Err(format!("unknown governance op: {op}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, effect: &str, prio: i64, conds: Value) -> RuleIn {
        serde_json::from_value(json!({
            "rule_id": id, "name": id, "description": "", "target_scope": "global",
            "conditions": conds, "effect": effect, "priority": prio, "version": "1"
        })).unwrap()
    }

    #[test]
    fn fail_closed_no_match() {
        let rules = vec![rule("r1", "allow", 1, json!([{"field": "action", "operator": "eq", "value": "read"}]))];
        let d = evaluate(&rules, &json!({"action": "write"})).unwrap();
        assert_eq!(d["effect"], json!("deny"));
        assert_eq!(d["matched_rules"], json!([]));
    }

    #[test]
    fn deny_is_terminal_and_priority_ordered() {
        let rules = vec![
            rule("allow_all", "allow", 10, json!([{"field": "action", "operator": "exists", "value": null}])),
            rule("deny_write", "deny", 1, json!([{"field": "action", "operator": "eq", "value": "write"}])),
        ];
        let d = evaluate(&rules, &json!({"action": "write", "correlation_id": "c1"})).unwrap();
        assert_eq!(d["effect"], json!("deny"));
        assert_eq!(d["denied_by"], json!("deny_write"));
    }

    #[test]
    fn rejects_disallowed_field() {
        let rules = vec![rule("r", "allow", 1, json!([{"field": "secret", "operator": "eq", "value": 1}]))];
        assert!(evaluate(&rules, &json!({})).is_err());
    }
}
