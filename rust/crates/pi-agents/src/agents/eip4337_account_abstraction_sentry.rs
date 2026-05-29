//! Port of `pi_micro_agents/pi_eip4337_account_abstraction_sentry.py`.
//!
//! Audits Solidity Smart Accounts / Paymasters for ERC-4337 bundler simulation
//! restrictions: validation functions (`validateUserOp` /
//! `validatePaymasterUserOp`) must not access forbidden global state such as
//! `tx.origin`, `block.blockhash`, `block.timestamp`, `block.number` or
//! `gasleft()`. Behaviour is a line-for-line mirror of the Python original.

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

// Mirrors: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Python `.` does not match newlines by default; neither does Rust's. `[\s\S]`
// matches everything (incl. newlines) in both engines. Non-greedy semantics are
// identical between Python `re` and the Rust `regex` crate.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Forbidden global-state patterns, in the exact order the Python list declares
// them. Each tuple is (compiled regex, human-readable keyword).
static FORBIDDEN_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"\btx\.origin\b").unwrap(), "tx.origin"),
        (Regex::new(r"\bblock\.blockhash\b").unwrap(), "block.blockhash"),
        (Regex::new(r"\bblock\.timestamp\b").unwrap(), "block.timestamp"),
        (Regex::new(r"\bblock\.number\b").unwrap(), "block.number"),
        (Regex::new(r"\bgasleft\s*\(").unwrap(), "gasleft()"),
    ]
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original additionally falls back to a
/// `~/.antigravitycli/config.json` (or repo-relative) file when the env var is
/// unset, returning `bool(data.get("PI_AA_SENTRY_STRICT_MODE", True))`. With no
/// such file present the Python default is `True`, which this env-only mirror
/// reproduces exactly. See parity deviations.
fn is_strict_mode() -> bool {
    match std::env::var("PI_AA_SENTRY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_account_abstraction(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // args (group 2) is captured by Python but unused in the loop body.
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check for paymaster or account abstraction validation methods:
        // validateUserOp, validatePaymasterUserOp
        if name.contains("validateUserOp") || name.contains("validatePaymasterUserOp") {
            // ERC-4337 bans accessing global block metadata, blockhash,
            // gasleft, tx.origin, timestamp, number etc.
            for (pattern, keyword) in FORBIDDEN_PATTERNS.iter() {
                if pattern.is_match(body) {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Validation function '{name}' accesses forbidden global state parameter '{keyword}'. \
This violates ERC-4337 bundler simulation restrictions, causing transaction rejection."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_AA_RISK".to_string();
        } else {
            status = "WARN_AA_RISK".to_string();
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
    let out = audit_account_abstraction(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_account_abstraction(&Input {
            file_path: "f.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_code_passes() {
        std::env::remove_var("PI_AA_SENTRY_STRICT_MODE");
        let o = run(
            "contract A { function validateUserOp(UserOp op) external returns (uint256) { return 0; } }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn tx_origin_in_validate_rejected_strict() {
        std::env::set_var("PI_AA_SENTRY_STRICT_MODE", "true");
        let o = run(
            "function validateUserOp(UserOp op) external { require(tx.origin == owner); }",
        );
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_AA_RISK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["validateUserOp"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn warn_path_coerces_secure_when_not_strict() {
        std::env::set_var("PI_AA_SENTRY_STRICT_MODE", "false");
        let o = run(
            "function validatePaymasterUserOp(UserOp op) external { uint t = block.timestamp; }",
        );
        // is_secure is coerced back to true in non-strict mode
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_AA_RISK");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["validatePaymasterUserOp"]);
        std::env::remove_var("PI_AA_SENTRY_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn non_validation_function_ignored() {
        std::env::remove_var("PI_AA_SENTRY_STRICT_MODE");
        let o = run("function harmless() public { uint x = block.number; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
