//! Port of `pi_micro_agents/pi_database_migration_unindexed_sentry.py`.
//!
//! Audits migration / schema scripts for foreign keys or search fields that are
//! missing indexes. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub migration_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// `re.search(r'\b[a-zA-Z0-9_]+_id\b', ...)`. No lookaround / backreferences, so
/// this maps directly onto the `regex` crate.
static ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9_]+_id\b").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_migration_indexes(input: &Input) -> Output {
    let code = &input.migration_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Precompute the lowercased full code once; Python recomputes `code.lower()`
    // inside the loop but the result is identical for every iteration.
    let code_lower = code.to_lowercase();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        let clean_lower = clean_line.to_lowercase();
        if clean_lower.contains("foreign_key")
            || clean_lower.contains("references")
            || ID_RE.is_match(&clean_lower)
        {
            // Check the WHOLE migration body (Python checks `code.lower()`, not
            // just the line) for any index-ish keyword.
            let has_index_kw = ["index", "add_index", "create index", "unique_key"]
                .iter()
                .any(|kw| code_lower.contains(kw));
            if !has_index_kw {
                vulnerable_elements.push(format!("Line {idx}"));
                flagged_findings.push(format!(
                    "Line {idx}: Potential foreign key or search field missing index: '{clean_line}'. \
Omitting indexes on foreign keys leads to serious table-scan performance degradation during joins or deletes."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 60.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DATABASE_MIGRATION_UNINDEXED".to_string();
        } else {
            status = "WARN_DATABASE_MIGRATION_UNINDEXED".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_migration_indexes(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_migration_indexes(&Input {
            file_path: "m.rb".into(),
            migration_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn indexed_code_passes() {
        // Contains "index", so even the user_id line is not flagged.
        let o = run("add_column :posts, :user_id\nadd_index :posts, :user_id");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn unindexed_foreign_key_flagged() {
        let o = run("user_id INT");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DATABASE_MIGRATION_UNINDEXED");
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn references_keyword_flagged() {
        let o = run("t.references :users");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn empty_code_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
