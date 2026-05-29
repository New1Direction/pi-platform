//! Port of `pi_micro_agents/pi_semantic_schema_dynamic_field_check.py`.
//!
//! Audits database schemas for dynamic / unstructured fields (raw JSON, Dict,
//! pickle, text columns) that lack a corresponding strict nested sub-model.
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub schema_code: String,
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

/// Mirrors the Python module-level regex:
/// `r'([a-zA-Z0-9_]+)\s*=\s*(?:Column\s*\(\s*(?:JSON|PickleType|text)\s*\)|JSONColumn)'`
/// compiled with `re.IGNORECASE` -> `(?i)` prefix.
static DYNAMIC_FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)([a-zA-Z0-9_]+)\s*=\s*(?:Column\s*\(\s*(?:JSON|PickleType|text)\s*\)|JSONColumn)",
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`: returns True unless the env var is set, in which
/// case it is True iff the value (lowercased) equals "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_dynamic_fields(input: &Input) -> Output {
    let code = &input.schema_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // re.finditer over the regex; group(1) is the column name.
    for caps in DYNAMIC_FIELD_RE.captures_iter(code) {
        let col_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // Simple check: see if there's any validator or nested type with the
        // same column name prefix/suffix.
        let has_submodel = code.contains(&format!("{col_name}_schema"))
            || code.contains(&format!("{col_name}_model"))
            || code.contains("Dict[str,");
        if !has_submodel {
            vulnerable_elements.push(col_name.to_string());
            flagged_findings.push(format!(
                "Dynamic raw database field '{col_name}' lacks a corresponding nested sub-model or strict type validator. \
Unconstrained dynamic columns permit arbitrary payload insertions, risking NoSQL/SQL injections or application logic bypass."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SEMANTIC_SCHEMA_DYNAMIC_FIELD".to_string();
        } else {
            status = "WARN_SEMANTIC_SCHEMA_DYNAMIC_FIELD".to_string();
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
    let out = audit_dynamic_fields(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_dynamic_fields(&Input {
            file_path: "models.py".into(),
            schema_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_schema_passes() {
        let o = run("name = Column(String(50))\nage = Column(Integer)");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn dynamic_json_column_flagged() {
        let o = run("payload = Column(JSON)");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SEMANTIC_SCHEMA_DYNAMIC_FIELD");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_elements, vec!["payload"]);
    }

    #[test]
    fn jsoncolumn_and_pickle_flagged() {
        let o = run("data = JSONColumn\nblob = Column(PickleType)");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["data", "blob"]);
    }

    #[test]
    fn submodel_present_suppresses_finding() {
        // payload_schema present -> has_submodel True -> not flagged
        let o = run("payload = Column(JSON)\npayload_schema = PayloadModel");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_elements.is_empty());
    }
}
