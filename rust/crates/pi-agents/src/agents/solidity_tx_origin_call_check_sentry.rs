//! Port of `pi_micro_agents/pi_solidity_tx_origin_call_check_sentry.py`.
//!
//! Audits Solidity contracts for vulnerable `tx.origin` authentication checks,
//! especially in fallback/receive handlers. Behaviour is a line-for-line mirror
//! of the Python original.

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
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors the Python `re.findall` pattern on line 44. Two capture groups:
//   group 1 -> the function/fallback/receive declaration
//   group 2 -> the body (via `[\s\S]*?`, matches any char including newlines)
// No lookaround/backreferences, so the Rust `regex` crate is byte-compatible.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(function\s+[a-zA-Z0-9_]+\s*\(.*?\)|fallback\s*\(.*?\)|receive\s*\(.*?\))[^{]*\{([\s\S]*?)\}",
    )
    .unwrap()
});

pub fn audit_tx_origin_call(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions including fallback and receive
    for caps in FUNC_RE.captures_iter(code) {
        let decl = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");

        // Check if tx.origin is used for authorization
        if body.contains("tx.origin")
            && (body.contains("require") || body.contains("assert") || body.contains("if"))
        {
            let name = pyutil::strip(decl);
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Handler '{name}' utilizes 'tx.origin' for verification or authorization checks. \
Using tx.origin for authentication makes the contract vulnerable to phishing attacks (swapping identity of callers via intermediate malicious contracts)."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TX_ORIGIN_CALL_CHECK".to_string();
        } else {
            status = "WARN_TX_ORIGIN_CALL_CHECK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_functions: vulnerable_funcs,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_tx_origin_call(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_tx_origin_call(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("contract C { function safe() public { x = 1; } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn tx_origin_require_flagged() {
        let o = run("contract C { function withdraw() public { require(tx.origin == owner); } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TX_ORIGIN_CALL_CHECK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_functions, vec!["function withdraw()"]);
    }

    #[test]
    fn fallback_with_tx_origin_if_flagged() {
        let o = run("contract C { fallback() external payable { if (tx.origin == owner) { revert(); } } }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["fallback()"]);
    }
}
