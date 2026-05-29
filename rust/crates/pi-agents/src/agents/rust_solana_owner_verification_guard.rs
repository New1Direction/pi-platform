//! Port of `pi_micro_agents/pi_rust_solana_owner_verification_guard.py`.
//!
//! Specialized Rust/Solana micro-agent that audits instruction endpoints for
//! missing Account Owner verification checks. Behaviour is a line-for-line
//! mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict (`true`) unless the env var is set, in
/// which case it is strict only when the value (case-insensitively) equals
/// "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
//
// No lookahead/lookbehind/backreferences are used, so the Rust `regex` crate
// reproduces this pattern verbatim. As in Python (no DOTALL flag), `.` does
// not match newlines, while `[\s\S]` matches everything including newlines.
static METHOD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

pub fn audit_owner_verification(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // `re.findall` with 3 capture groups yields (name, args, body) tuples.
    for caps in METHOD_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let args = caps.get(2).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        if args.contains("AccountInfo") || body.contains("AccountInfo") {
            // If there are user accounts, check if the owner is checked
            if !body.contains("owner") && !body.contains("program_id") && !body.contains("Owner") {
                vulnerable_elements.push(name.to_string());
                flagged_findings.push(format!(
                    "Instruction handler '{name}' processes accounts but does not verify account owners. \
Without verifying that the account's owner is the expected program ID, malicious actors can pass spoofed state accounts."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SOLANA_OWNER_VERIFICATION".to_string();
        } else {
            status = "WARN_SOLANA_OWNER_VERIFICATION".to_string();
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
    let out = audit_owner_verification(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_owner_verification(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        // Body verifies owner == program_id, so not flagged.
        let o = run("fn safe(a: AccountInfo) { require(a.owner == program_id); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn missing_owner_check_flagged() {
        let o = run("fn process(ctx: AccountInfo) { let x = 1; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_OWNER_VERIFICATION");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["process"]);
    }

    #[test]
    fn no_account_info_is_secure() {
        // No AccountInfo in args or body -> never flagged.
        let o = run("fn helper(x: u64) { let y = x + 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
