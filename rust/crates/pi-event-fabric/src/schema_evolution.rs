//! Deterministic core of `pi_event_fabric/schema/evolution.py`:
//! schema fingerprinting, compatibility validation, migration-path BFS, and
//! data migration. (The SQLite `SchemaRegistry` CRUD is persistence plumbing
//! with `datetime('now')` timestamps — non-deterministic, mechanical, and
//! scoped out of this parity port.)

use crate::canonical::dumps_canonical;
use crate::event::sha256_hex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};

fn default_true() -> bool {
    true
}

#[derive(Deserialize, Clone)]
pub struct FieldIn {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub default: Value,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub nested_schema_fingerprint: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct SchemaIn {
    pub schema_name: String,
    pub version: String,
    pub fields: Vec<FieldIn>,
    pub compatibility: String,
}

fn field_to_dict(f: &FieldIn) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), json!(f.name));
    m.insert("type".into(), json!(f.ty));
    m.insert("required".into(), json!(f.required));
    m.insert("default".into(), f.default.clone());
    m.insert("description".into(), json!(f.description));
    if let Some(nf) = &f.nested_schema_fingerprint {
        m.insert("nested_schema_fingerprint".into(), json!(nf));
    }
    Value::Object(m)
}

/// Mirrors `ArtifactSchema._canonical_json` (fields sorted by name) + fingerprint.
pub fn canonical_schema_json(s: &SchemaIn) -> String {
    let mut fields = s.fields.clone();
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    let arr: Vec<Value> = fields.iter().map(field_to_dict).collect();
    let mut m = Map::new();
    m.insert("schema_name".into(), json!(s.schema_name));
    m.insert("version".into(), json!(s.version));
    m.insert("fields".into(), Value::Array(arr));
    m.insert("compatibility".into(), json!(s.compatibility));
    dumps_canonical(&Value::Object(m))
}

pub fn fingerprint(s: &SchemaIn) -> String {
    sha256_hex(&canonical_schema_json(s))
}

/// Allowed change types per compatibility level (mirrors `CompatibilityValidator.RULES`).
fn allowed_changes(level: &str) -> HashSet<&'static str> {
    match level {
        "none" => [
            "field_added_optional", "field_added_required", "field_removed",
            "field_type_changed", "field_default_changed", "nested_schema_changed",
            "constraint_changed", "enum_variant_added", "enum_variant_removed",
        ].into_iter().collect(),
        "backward" => [
            "field_added_optional", "field_default_changed", "enum_variant_added",
            "nested_schema_changed",
        ].into_iter().collect(),
        "forward" => [
            "field_removed", "enum_variant_removed", "field_default_changed",
            "nested_schema_changed",
        ].into_iter().collect(),
        _ => HashSet::new(), // "full" or unknown: no changes allowed
    }
}

/// Mirrors `CompatibilityValidator._diff`, preserving Python's iteration order:
/// added (new.fields order), removed (old.fields order), modified (old.fields order).
fn diff(old: &SchemaIn, new: &SchemaIn) -> Vec<Value> {
    let old_names: HashSet<&str> = old.fields.iter().map(|f| f.name.as_str()).collect();
    let new_map: HashMap<&str, &FieldIn> = new.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let old_map: HashMap<&str, &FieldIn> = old.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let mut changes = Vec::new();

    for f in &new.fields {
        if !old_names.contains(f.name.as_str()) {
            let ty = if f.required { "field_added_required" } else { "field_added_optional" };
            changes.push(json!({"type": ty, "field": f.name, "required": f.required}));
        }
    }
    for f in &old.fields {
        if !new_map.contains_key(f.name.as_str()) {
            changes.push(json!({"type": "field_removed", "field": f.name}));
        }
    }
    for f in &old.fields {
        if let Some(n) = new_map.get(f.name.as_str()) {
            let o = old_map[f.name.as_str()];
            if o.ty != n.ty {
                changes.push(json!({"type": "field_type_changed", "field": f.name}));
            }
            if o.default != n.default {
                changes.push(json!({"type": "field_default_changed", "field": f.name}));
            }
            if o.nested_schema_fingerprint != n.nested_schema_fingerprint {
                changes.push(json!({"type": "nested_schema_changed", "field": f.name}));
            }
        }
    }
    changes
}

/// Mirrors `CompatibilityValidator.validate` -> CompatibilityReport (as JSON).
pub fn validate(old: &SchemaIn, new: &SchemaIn) -> Value {
    let changes = diff(old, new);
    let allowed = allowed_changes(&new.compatibility);
    let mut violations = Vec::new();
    for c in &changes {
        let t = c["type"].as_str().unwrap_or("");
        if !allowed.contains(t) {
            // Python interpolates the SchemaChangeType *enum instance*; on a
            // (str, Enum) member `f"{member}"` yields "ClassName.MEMBER_NAME"
            // (the name is the value upper-cased), NOT the value.
            violations.push(format!(
                "SchemaChangeType.{} not allowed under {} compatibility",
                t.to_uppercase(),
                new.compatibility
            ));
        }
    }
    json!({
        "old_fingerprint": fingerprint(old),
        "new_fingerprint": fingerprint(new),
        "compatible": violations.is_empty(),
        "level": new.compatibility,
        "changes": changes,
        "violations": violations,
    })
}

// ── Migration DAG (BFS path) ────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct StepIn {
    pub migration_id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    #[serde(default)]
    pub transformation_type: String,
    #[serde(default)]
    pub field_name: String,
    #[serde(default)]
    pub parameters: Value,
}

/// Mirrors `MigrationDAG.find_path` — shortest path BFS (registration order
/// preserved within each from-node, like Python's per-key list).
pub fn find_path(steps: &[StepIn], from_fp: &str, to_fp: &str, max_hops: usize) -> Vec<StepIn> {
    if from_fp == to_fp {
        return vec![];
    }
    let mut forward: HashMap<&str, Vec<&StepIn>> = HashMap::new();
    for s in steps {
        forward.entry(s.from_fingerprint.as_str()).or_default().push(s);
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, Vec<StepIn>)> = VecDeque::new();
    queue.push_back((from_fp.to_string(), vec![]));
    while let Some((current, path)) = queue.pop_front() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());
        for step in forward.get(current.as_str()).into_iter().flatten() {
            let mut new_path = path.clone();
            new_path.push((*step).clone());
            if step.to_fingerprint == to_fp {
                return new_path;
            }
            if new_path.len() < max_hops {
                queue.push_back((step.to_fingerprint.clone(), new_path));
            }
        }
    }
    vec![]
}

/// Mirrors `apply_migration` for the deterministic built-in transforms.
/// ("custom" uses a Python callable — not portable; left as a no-op pass-through.)
pub fn apply_migration(data: &Value, step: &StepIn, direction: &str) -> Value {
    let mut result = match data {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    let p = &step.parameters;
    match step.transformation_type.as_str() {
        "add_field" => {
            if direction == "forward" {
                if !result.contains_key(&step.field_name) {
                    result.insert(step.field_name.clone(), p.get("default").cloned().unwrap_or(Value::Null));
                }
            } else {
                result.remove(&step.field_name);
            }
        }
        "remove_field" => {
            if direction == "forward" {
                result.remove(&step.field_name);
            } else {
                result.insert(step.field_name.clone(), p.get("restore_value").cloned().unwrap_or(Value::Null));
            }
        }
        "rename_field" => {
            let old_name = p.get("old_name").and_then(|v| v.as_str()).unwrap_or("");
            let new_name = p.get("new_name").and_then(|v| v.as_str()).unwrap_or("");
            if direction == "forward" {
                if let Some(v) = result.remove(old_name) {
                    result.insert(new_name.to_string(), v);
                }
            } else if let Some(v) = result.remove(new_name) {
                result.insert(old_name.to_string(), v);
            }
        }
        _ => {}
    }
    Value::Object(result)
}

pub fn migrate_data(data: &Value, steps: &[StepIn], from_fp: &str, to_fp: &str, direction: &str) -> Result<Value, String> {
    let path = find_path(steps, from_fp, to_fp, 5);
    if path.is_empty() && from_fp != to_fp {
        return Err(format!("No migration path from {from_fp} to {to_fp}"));
    }
    let mut result = data.clone();
    for step in &path {
        result = apply_migration(&result, step, direction);
    }
    Ok(result)
}

/// JSON dispatch used by the PyO3 bridge / parity harness.
pub fn dispatch(op: &str, args: &Value) -> Result<Value, String> {
    match op {
        "fingerprint" => {
            let s: SchemaIn = serde_json::from_value(args["schema"].clone()).map_err(|e| e.to_string())?;
            Ok(json!(fingerprint(&s)))
        }
        "validate" => {
            let old: SchemaIn = serde_json::from_value(args["old"].clone()).map_err(|e| e.to_string())?;
            let new: SchemaIn = serde_json::from_value(args["new"].clone()).map_err(|e| e.to_string())?;
            Ok(validate(&old, &new))
        }
        "find_path" => {
            let steps: Vec<StepIn> = serde_json::from_value(args["steps"].clone()).map_err(|e| e.to_string())?;
            let from = args["from"].as_str().unwrap_or("");
            let to = args["to"].as_str().unwrap_or("");
            let max = args.get("max_hops").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
            let path = find_path(&steps, from, to, max);
            Ok(json!(path.iter().map(|s| s.migration_id.clone()).collect::<Vec<_>>()))
        }
        "migrate_data" => {
            let data = args["data"].clone();
            let steps: Vec<StepIn> = serde_json::from_value(args["steps"].clone()).map_err(|e| e.to_string())?;
            let from = args["from"].as_str().unwrap_or("");
            let to = args["to"].as_str().unwrap_or("");
            let direction = args.get("direction").and_then(|v| v.as_str()).unwrap_or("forward");
            migrate_data(&data, &steps, from, to, direction)
        }
        _ => Err(format!("unknown schema op: {op}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(level: &str, fields: Value) -> SchemaIn {
        serde_json::from_value(json!({
            "schema_name": "Artifact", "version": "1", "compatibility": level, "fields": fields
        })).unwrap()
    }

    #[test]
    fn backward_allows_optional_add() {
        let old = schema("backward", json!([{"name": "a", "type": "str"}]));
        let new = schema("backward", json!([{"name": "a", "type": "str"}, {"name": "b", "type": "int", "required": false}]));
        let r = validate(&old, &new);
        assert_eq!(r["compatible"], json!(true));
    }

    #[test]
    fn backward_rejects_required_add() {
        let old = schema("backward", json!([{"name": "a", "type": "str"}]));
        let new = schema("backward", json!([{"name": "a", "type": "str"}, {"name": "b", "type": "int", "required": true}]));
        let r = validate(&old, &new);
        assert_eq!(r["compatible"], json!(false));
    }
}
