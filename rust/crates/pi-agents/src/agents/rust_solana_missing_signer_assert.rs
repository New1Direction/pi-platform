//! Port of `pi_micro_agents/pi_rust_solana_missing_signer_assert.py`.
//!
//! Specialized Rust/Solana micro-agent that audits instruction definitions for
//! missing user signer checks. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
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
    match std::env::var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Three capture groups (name, args, body). No lookaround/backreferences, so this
// translates directly. The Rust `regex` crate honours the lazy quantifiers
// (`.*?`, `[\s\S]*?`) and `.` does NOT match newlines by default in either
// engine, matching CPython's behaviour exactly.
static METHOD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

pub fn audit_missing_signer(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in METHOD_RE.captures_iter(code) {
        let name = &caps[1];
        let args = &caps[2];
        let body = &caps[3];

        if args.contains("AccountInfo") || body.contains("AccountInfo") {
            // If there are user accounts, check if .is_signer is asserted
            if !body.contains("is_signer")
                && !body.contains("Signer")
                && !body.to_lowercase().contains("signer")
            {
                vulnerable_elements.push(name.to_string());
                flagged_findings.push(format!(
                    "Instruction handler '{name}' processes accounts but does not verify account signatures. \
Without checking .is_signer or requiring a Signer type, anyone can spoof this account's authority."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_MISSING_SIGNER".to_string();
        } else {
            status = "WARN_SOLANA_MISSING_SIGNER".to_string();
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
    let out = audit_missing_signer(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_missing_signer(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_handler_with_is_signer_passes() {
        std::env::remove_var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE");
        let o = run("pub fn handler(account: AccountInfo) { if !account.is_signer { return; } }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    #[serial]
    fn missing_signer_check_flagged_strict() {
        std::env::remove_var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE");
        let o = run("pub fn handler(account: AccountInfo) { transfer(account); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_MISSING_SIGNER");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_elements, vec!["handler"]);
    }

    #[test]
    #[serial]
    fn missing_signer_warn_when_not_strict() {
        std::env::set_var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE", "false");
        let o = run("pub fn handler(account: AccountInfo) { transfer(account); }");
        std::env::remove_var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE");
        // not strict -> WARN path, is_secure coerced back to True
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_SOLANA_MISSING_SIGNER");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_elements, vec!["handler"]);
    }

    #[test]
    #[serial]
    fn no_account_info_is_ignored() {
        std::env::remove_var("PI_SOLANA_MISSING_SIGNER_STRICT_MODE");
        let o = run("pub fn helper(x: u64) -> u64 { x + 1 }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
