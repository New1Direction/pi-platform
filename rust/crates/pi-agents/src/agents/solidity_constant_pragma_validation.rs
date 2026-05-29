//! Port of `pi_micro_agents/pi_solidity_constant_pragma_validation.py`.
//!
//! Audits Solidity contracts for floating compiler version pragmas
//! (e.g. `^0.8.0`, `>=0.8.0`). Behaviour is a line-for-line mirror of the
//! Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub solidity_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// `re.search(r'pragma\s+solidity\s+([^;]+);', code)`.
/// One capture group, no lookaround/backrefs, so a direct port is safe.
static PRAGMA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pragma\s+solidity\s+([^;]+);").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_CONSTANT_PRAGMA_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_constant_pragma(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find pragma statement
    if let Some(caps) = PRAGMA_RE.captures(code) {
        let version_expr = pyutil::strip(caps.get(1).unwrap().as_str());
        // Floating characters: ^, >, <, >=, <=
        let is_floating = version_expr.contains('^')
            || version_expr.contains('>')
            || version_expr.contains('<');

        if is_floating {
            flagged_findings.push(format!(
                "Solidity file utilizes floating pragma compiler definition 'pragma solidity {version_expr};'. \
Production contracts should lock the compiler version to a specific release (e.g., 0.8.20) \
to prevent accidental compilation under untested versions containing unknown optimizer bugs or compiler defects."
            ));
        }
    }

    let mut is_secure = flagged_findings.is_empty();
    let risk_score = if !is_secure { 50.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_CONSTANT_PRAGMA".to_string();
        } else {
            status = "WARN_CONSTANT_PRAGMA".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_constant_pragma(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_constant_pragma(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn locked_pragma_passes() {
        let o = run("pragma solidity 0.8.20;");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn caret_floating_pragma_flagged() {
        let o = run("pragma solidity ^0.8.0;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CONSTANT_PRAGMA");
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn range_floating_pragma_flagged() {
        let o = run("pragma solidity >=0.8.0 <0.9.0;");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 50.0);
    }

    #[test]
    fn no_pragma_passes() {
        let o = run("contract Foo {}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
