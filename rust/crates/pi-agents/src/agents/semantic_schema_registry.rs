//! Port of `pi_micro_agents/pi_semantic_schema_registry.py`.
//!
//! Specialized database micro-agent that audits migrations or schemas for
//! dynamic column shifts lacking integrity bounds (raw JSON column types,
//! dynamic schema fields, validation bypass). Behaviour is a line-for-line
//! mirror of the Python original `audit_schema_registry`.

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

/// `re.search(r'(JSON1|dynamic_schema|unstructured_data|Column\(\s*JSON\s*\)|BypassValidation)', code)`.
///
/// Single capture group wrapping the full alternation. No lookaround /
/// backreferences, so this is a direct, faithful port. `re.search` returns the
/// leftmost match; `group(1)` equals `group(0)` here since the whole pattern is
/// the captured group.
static UNSTRUCTURED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(JSON1|dynamic_schema|unstructured_data|Column\(\s*JSON\s*\)|BypassValidation)")
        .unwrap()
});

/// Mirrors `is_strict_mode()` from the Python source.
///
/// Resolution order:
///   1. If the env var `PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE` is set, return
///      `value.lower() == "true"`.
///   2. Else look for `~/.antigravitycli/config.json`; if absent, fall back to
///      the repo-root `.antigravitycli/config.json` (Python resolves this from
///      the agent module's directory: `<module>/../../.antigravitycli/...`).
///   3. If a config file is found and parses, return
///      `bool(data.get("PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE", True))`.
///   4. Otherwise default to `true`.
///
/// NOTE: a compiled Rust binary cannot recover the Python module's source path,
/// so the repo-relative fallback is resolved relative to the current working
/// directory (`./.antigravitycli/config.json`). See parity deviations.
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // Primary: ~/.antigravitycli/config.json
    let mut config_path: Option<std::path::PathBuf> = None;
    if let Ok(home) = std::env::var("HOME") {
        let p = std::path::Path::new(&home).join(".antigravitycli/config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }
    // Fallback: repo-root .antigravitycli/config.json (best-effort: CWD-relative).
    if config_path.is_none() {
        let p = std::path::PathBuf::from(".antigravitycli/config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }

    if let Some(p) = config_path {
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                // bool(data.get("PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE", True))
                return match data.get("PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE") {
                    Some(v) => py_bool(v),
                    None => true,
                };
            }
        }
    }
    true
}

/// Reproduce Python `bool(x)` truthiness for the JSON value found in config.
fn py_bool(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else if let Some(f) = n.as_f64() {
                f != 0.0
            } else {
                true
            }
        }
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

pub fn audit_schema_registry(input: &Input) -> Output {
    let code = &input.schema_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find dynamic schema shifts, unstructured fields with wildcards, or lack of
    // primary constraints. E.g. raw JSON field types or wildcards in schema
    // validations that allow arbitrary inputs.
    if let Some(caps) = UNSTRUCTURED_RE.captures(code) {
        let g1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        vulnerable_elements.push(g1.to_string());
        flagged_findings.push(format!(
            "Schema definition uses an unconstrained dynamic columns configuration: '{g1}'. \
Allowing arbitrary unstructured column inputs without strict type bounds triggers payload injection \
or downstream query injection exploits."
        ));
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 60.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SCHEMA_REGISTRY".to_string();
        } else {
            status = "WARN_SCHEMA_REGISTRY".to_string();
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
    let out = audit_schema_registry(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_schema_registry(&Input {
            file_path: "migration.py".into(),
            schema_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_schema_passes() {
        let o = run("CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(50));");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn json_column_flagged() {
        let o = run("payload = Column( JSON )");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.vulnerable_elements, vec!["Column( JSON )"]);
        // Default (no env) is strict mode unless a config file overrides it.
        // We avoid asserting the exact status string here because it depends on
        // process env / config-file state; risk + flag presence is the invariant.
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn dynamic_schema_token_captured() {
        let o = run("field = dynamic_schema()");
        assert!(!o.is_secure || o.status == "WARN_SCHEMA_REGISTRY");
        assert_eq!(o.vulnerable_elements, vec!["dynamic_schema"]);
        assert_eq!(o.risk_score, 60.0);
    }

    #[test]
    fn bypass_validation_token_captured() {
        let o = run("BypassValidation = True");
        assert_eq!(o.vulnerable_elements, vec!["BypassValidation"]);
        assert_eq!(o.risk_score, 60.0);
    }
}
