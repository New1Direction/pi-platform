//! Port of `pi_micro_agents/pi_dimensional_analysis_sentry.py`.
//!
//! Specialized financial & unit governance micro-agent. Scans arithmetic
//! assignments for mixed-unit ("dimensional") collisions using a caller-supplied
//! unit registry. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use regex::Regex;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Insertion-ordered string->string map.
///
/// Python `dict` preserves insertion order, and `audit_dimensions` iterates
/// `registry.keys()` in that order to build `matched_vars`, with
/// `matched_vars[0]` (the *first*-inserted matching var) used as the reference
/// unit. `serde_json::Map` without the `preserve_order` feature is a `BTreeMap`
/// (sorted), which would break parity. This wrapper deserializes the JSON object
/// in document order into a `Vec<(String, String)>`, faithfully reproducing the
/// Python dict semantics needed here.
#[derive(Debug, Default)]
pub struct OrderedMap {
    entries: Vec<(String, String)>,
}

impl OrderedMap {
    /// Mirrors `registry.keys()` iteration order.
    fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.iter().map(|(k, _)| k)
    }

    /// Mirrors `registry[key]`. Returns the value for the *first* inserted entry
    /// with this key (matching how `dict[k]` behaves vs. duplicate keys parsed
    /// from JSON, where the last write wins — see note below). For the data this
    /// agent receives, keys are unique.
    fn get(&self, key: &str) -> Option<&String> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

impl<'de> Deserialize<'de> for OrderedMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedMapVisitor;

        impl<'de> Visitor<'de> for OrderedMapVisitor {
            type Value = OrderedMap;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of string to string")
            }

            fn visit_map<M>(self, mut access: M) -> Result<OrderedMap, M::Error>
            where
                M: MapAccess<'de>,
            {
                // serde_json yields entries in JSON document order, matching the
                // insertion order Python's dict would observe.
                let mut entries: Vec<(String, String)> = Vec::new();
                while let Some((k, v)) = access.next_entry::<String, String>()? {
                    // Python dict: a later duplicate key overwrites the earlier
                    // value but keeps the original position. Reproduce that.
                    if let Some(slot) = entries.iter_mut().find(|(ek, _)| *ek == k) {
                        slot.1 = v;
                    } else {
                        entries.push((k, v));
                    }
                }
                Ok(OrderedMap { entries })
            }
        }

        deserializer.deserialize_map(OrderedMapVisitor)
    }
}

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub source_code: String,
    pub unit_registry: OrderedMap,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub mismatches: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DIMENSIONAL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_dimensions(input: &Input) -> Output {
    let code = &input.source_code;
    let registry = &input.unit_registry;
    let mut mismatches: Vec<String> = Vec::new();

    for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        // Scan for math assignments (e.g., a = b + c)
        if line.contains('=')
            && (line.contains('+')
                || line.contains('-')
                || line.contains('*')
                || line.contains('/'))
        {
            // matched_vars = [var for var in registry.keys()
            //                  if re.search(r'\b' + re.escape(var) + r'\b', line)]
            let matched_vars: Vec<&String> = registry
                .keys()
                .filter(|var| {
                    let pattern = format!(r"\b{}\b", regex::escape(var));
                    // re.search: a match anywhere in the line.
                    Regex::new(&pattern).unwrap().is_match(line)
                })
                .collect();

            if matched_vars.len() > 1 {
                // Check if units differ
                let first_var = matched_vars[0];
                let first_unit = registry.get(first_var).expect("matched var present");
                for var in &matched_vars[1..] {
                    let var_unit = registry.get(*var).expect("matched var present");
                    if var_unit != first_unit {
                        mismatches.push(format!(
                            "L{idx}: Mixed units in expression: '{first_var}' ({first_unit}) \
vs '{var}' ({var_unit}) in: {}",
                            pyutil::strip(line)
                        ));
                    }
                }
            }
        }
    }

    let mut is_secure = mismatches.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_DIMENSION_RISK".to_string();
        } else {
            status = "WARN_DIMENSION_RISK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        mismatches,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_dimensions(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(source: &str, registry: &[(&str, &str)]) -> Input {
        let entries = registry
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Input {
            file_path: "f.sol".into(),
            source_code: source.into(),
            unit_registry: OrderedMap { entries },
        }
    }

    #[test]
    fn consistent_units_pass() {
        let o = audit_dimensions(&input(
            "total = a + b",
            &[("a", "wei"), ("b", "wei"), ("total", "wei")],
        ));
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.mismatches.is_empty());
    }

    #[test]
    fn mixed_units_rejected_in_strict_mode() {
        // Ensure non-strict env is not leaking from another test.
        std::env::remove_var("PI_DIMENSIONAL_STRICT_MODE");
        let o = audit_dimensions(&input("c = a + b", &[("a", "wei"), ("b", "gwei")]));
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DIMENSION_RISK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.mismatches.len(), 1);
        assert!(o.mismatches[0].starts_with("L1: Mixed units in expression: 'a' (wei) vs 'b' (gwei)"));
    }

    #[test]
    fn no_arithmetic_no_mismatch() {
        // Assignment with no +,-,*,/ should be skipped entirely.
        let o = audit_dimensions(&input("x = y", &[("x", "wei"), ("y", "gwei")]));
        assert!(o.is_secure);
        assert!(o.mismatches.is_empty());
        assert_eq!(o.status, "PASSED");
    }
}
