//! Port of `pi_micro_agents/pi_architecture_import_boundary_sentry.py`.
//!
//! Deterministic micro-agent that audits import lines to prevent cross-layer
//! architectural boundary violations. Behaviour is a line-for-line mirror of the
//! Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Insertion-ordered map of `String -> Vec<String>`.
///
/// Python `dict` preserves insertion order, and `check_import_boundaries`
/// iterates `forbidden_mappings.items()` in that order to build `matching_rules`,
/// then iterates `matching_rules` (still in insertion order) when emitting
/// `violated_imports`. The order of emitted violations therefore depends on the
/// insertion order of the input mapping. `serde_json::Map` without the
/// `preserve_order` feature is a sorted `BTreeMap`, which would break parity, so
/// this wrapper deserializes the JSON object in document order into a
/// `Vec<(String, Vec<String>)>`.
#[derive(Debug, Default)]
pub struct OrderedMap {
    entries: Vec<(String, Vec<String>)>,
}

impl OrderedMap {
    /// Mirrors `forbidden_mappings.items()` iteration order.
    fn items(&self) -> impl Iterator<Item = &(String, Vec<String>)> {
        self.entries.iter()
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
                f.write_str("a map of string to list of strings")
            }

            fn visit_map<M>(self, mut access: M) -> Result<OrderedMap, M::Error>
            where
                M: MapAccess<'de>,
            {
                // serde_json yields entries in JSON document order, matching the
                // insertion order Python's dict would observe.
                let mut entries: Vec<(String, Vec<String>)> = Vec::new();
                while let Some((k, v)) = access.next_entry::<String, Vec<String>>()? {
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
    pub code_content: String,
    pub forbidden_mappings: OrderedMap,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub violated_imports: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Mirrors the two Python import patterns. Both are applied with `re.match`,
// which anchors at the start of the (single) line; the `^` anchor is explicit in
// the originals. Each has exactly one capture group.
static IMPORT_PATTERNS: Lazy<[Regex; 2]> = Lazy::new(|| {
    [
        Regex::new(r"^\s*import\s+([a-zA-Z0-9_\.]+)").unwrap(),
        Regex::new(r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import").unwrap(),
    ]
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_IMPORT_BOUNDARY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors Python `str.strip(".")`: removes leading and trailing '.' characters.
fn strip_dots(s: &str) -> &str {
    s.trim_matches('.')
}

pub fn check_import_boundaries(input: &Input) -> Output {
    let file_path = &input.file_path;
    let code = &input.code_content;
    let forbidden_mappings = &input.forbidden_mappings;
    let mut violated_imports: Vec<String> = Vec::new();

    // Find matching keys in forbidden_mappings (insertion order preserved).
    let mut matching_rules: Vec<&(String, Vec<String>)> = Vec::new();
    for entry in forbidden_mappings.items() {
        let (key, _forbidden_patterns) = entry;
        if file_path.contains(key.as_str()) {
            matching_rules.push(entry);
        }
    }

    if !matching_rules.is_empty() {
        for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
            let idx = i + 1;
            for pat in IMPORT_PATTERNS.iter() {
                if let Some(caps) = pat.captures(line) {
                    let imported_module = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    for (key, forbidden_patterns) in matching_rules.iter() {
                        for forbidden in forbidden_patterns.iter() {
                            let forbidden_norm = strip_dots(&forbidden.replace('/', ".")).to_string();
                            let module_norm =
                                strip_dots(&imported_module.replace('/', ".")).to_string();
                            if module_norm.contains(&forbidden_norm) {
                                violated_imports.push(format!(
                                    "Line {idx}: Import '{imported_module}' violates boundary rule for '{key}' (forbidden: '{forbidden}')"
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut is_secure = violated_imports.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_IMPORT_BOUNDARY".to_string();
        } else {
            status = "WARN_IMPORT_BOUNDARY".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        violated_imports,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_import_boundaries(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Input {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn clean_code_passes() {
        let input = parse(
            r#"{
                "file_path": "src/domain/order.py",
                "code_content": "import os\nfrom typing import List\n",
                "forbidden_mappings": {"src/domain": ["infrastructure"]}
            }"#,
        );
        let o = check_import_boundaries(&input);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.violated_imports.is_empty());
    }

    #[test]
    fn forbidden_import_rejected() {
        let input = parse(
            r#"{
                "file_path": "src/domain/order.py",
                "code_content": "import os\nfrom infrastructure.db import session\n",
                "forbidden_mappings": {"src/domain": ["infrastructure"]}
            }"#,
        );
        let o = check_import_boundaries(&input);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_IMPORT_BOUNDARY");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.violated_imports.len(), 1);
        assert_eq!(
            o.violated_imports[0],
            "Line 2: Import 'infrastructure.db' violates boundary rule for 'src/domain' (forbidden: 'infrastructure')"
        );
    }

    #[test]
    fn no_matching_rule_passes() {
        let input = parse(
            r#"{
                "file_path": "src/api/handler.py",
                "code_content": "from infrastructure.db import x\n",
                "forbidden_mappings": {"src/domain": ["infrastructure"]}
            }"#,
        );
        let o = check_import_boundaries(&input);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.violated_imports.is_empty());
    }

    #[test]
    fn slash_normalization_matches() {
        // forbidden "a/b" normalizes to "a.b" and matches module "a.b.c".
        let input = parse(
            r#"{
                "file_path": "x/y.py",
                "code_content": "import a.b.c",
                "forbidden_mappings": {"x/y": ["a/b"]}
            }"#,
        );
        let o = check_import_boundaries(&input);
        assert!(!o.is_secure);
        assert_eq!(o.violated_imports.len(), 1);
        assert!(o.violated_imports[0].contains("forbidden: 'a/b'"));
    }
}
