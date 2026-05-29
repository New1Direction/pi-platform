//! Port of `pi_micro_agents/pi_rust_solana_arithmetic_overflow_check.py`.
//!
//! Audits Rust/Solana smart-contract source for raw arithmetic operators
//! (`+`, `-`, `*`, `/`) that are not guarded by checked/safe math wrappers.
//! Behaviour is a line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict (true) unless the env var is set, in which
/// case it is strict only when the value equals (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_arithmetic_overflow(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        // Exclude comments
        let stripped = pyutil::strip(line);
        if stripped.starts_with("//") || stripped.starts_with("/*") || stripped.starts_with('*') {
            continue;
        }

        // Look for basic arithmetic operator usages that don't seem to be checked.
        let has_op = [" + ", " - ", " * ", " / "].iter().any(|op| line.contains(op));
        let has_safe = ["checked_", "safe_", "wrapping_", "saturating_", "assert"]
            .iter()
            .any(|safe| line.contains(safe));
        if has_op && !has_safe {
            vulnerable_elements.push(format!("Line {idx}"));
            flagged_findings.push(format!(
                "Line {idx}: Direct arithmetic operator without checked/safe wrapper: '{stripped}'. \
Unchecked math in Solana can lead to integer overflow/underflow, resulting in unauthorized token mints or logic bypasses."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_ARITHMETIC_OVERFLOW".to_string();
        } else {
            status = "WARN_SOLANA_ARITHMETIC_OVERFLOW".to_string();
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
    let out = audit_arithmetic_overflow(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_arithmetic_overflow(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn safe_checked_math_passes() {
        let o = run("let total = a.checked_add(b).unwrap();");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn raw_arithmetic_flagged() {
        let o = run("let total = a + b;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_ARITHMETIC_OVERFLOW");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn comment_lines_excluded() {
        let o = run("// let total = a + b;\n/* x - y */\n* doc - line");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
