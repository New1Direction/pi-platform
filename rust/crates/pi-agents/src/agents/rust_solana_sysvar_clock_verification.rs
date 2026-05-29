//! Port of `pi_micro_agents/pi_rust_solana_sysvar_clock_verification.py`.
//!
//! Audits Solana Rust contracts for clock manipulation or unsafe dependencies
//! on the Sysvar Clock. Behaviour is a line-for-line mirror of the Python
//! original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub rust_code: String,
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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_sysvar_clock(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let stripped = pyutil::strip(raw_line);
        if stripped.starts_with("//") || stripped.starts_with("/*") || stripped.starts_with('*') {
            continue;
        }

        // Look for references to Clock or unix_timestamp
        if raw_line.contains("Clock::")
            || raw_line.contains("unix_timestamp")
            || raw_line.contains("Clock::get")
        {
            // Check if there is high dependency on clock without standard safeguards
            vulnerable_elements.push(format!("Line {idx}"));
            flagged_findings.push(format!(
                "Line {idx}: Reference to Solana Sysvar Clock: '{stripped}'. \
Relying directly on clock time values can introduce mild manipulation risk or desynchronization issues in validator consensus."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 55.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_SYSVAR_CLOCK".to_string();
        } else {
            status = "WARN_SOLANA_SYSVAR_CLOCK".to_string();
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
    let out = audit_sysvar_clock(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_sysvar_clock(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("let x = 5;\nmsg!(\"hello\");");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn clock_get_flagged() {
        let o = run("let clock = Clock::get()?;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_SYSVAR_CLOCK");
        assert_eq!(o.risk_score, 55.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn unix_timestamp_flagged() {
        let o = run("let ts = clock.unix_timestamp;");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
        assert_eq!(o.risk_score, 55.0);
    }

    #[test]
    fn comment_lines_skipped() {
        // Comment lines starting with //, /*, or * are skipped even if they
        // reference Clock::.
        let o = run("// Clock::get() in a comment\n/* unix_timestamp */\n* Clock::");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
