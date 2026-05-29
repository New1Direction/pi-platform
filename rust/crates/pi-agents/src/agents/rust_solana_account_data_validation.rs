//! Port of `pi_micro_agents/pi_rust_solana_account_data_validation.py`.
//!
//! Audits Solana Rust smart contracts for dynamic accounts (functions that
//! touch `AccountInfo` data) that lack explicit size or boundary validations.
//! Behaviour is a line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strict iff its (case-insensitive) value is exactly "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_SOLANA_ACCOUNT_DATA_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors Python: re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// `.` does not match newlines by default in either engine, so `(.*?)` stays
// within a line for the args group; `[\s\S]*?` lazily matches the body across
// newlines until the first `}`.
static METHOD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

pub fn audit(input: &Input) -> Output {
    let code = &input.rust_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // for name, args, body in methods:
    for caps in METHOD_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        if body.contains("try_borrow_data")
            || body.contains("next_account_info")
            || body.contains("AccountInfo")
        {
            // has_size_check = any(kw in body for kw in [...])
            let has_size_check = ["len()", "try_from_slice", "size_of", "data_len", "assert"]
                .iter()
                .any(|kw| body.contains(kw));

            if !has_size_check {
                vulnerable_elements.push(name.to_string());
                flagged_findings.push(format!(
                    "Instruction handler/function '{name}' deserializes or processes AccountInfo data \
but does not perform explicit size or length verification checks. \
Omitting account size boundaries allows attackers to pass accounts with smaller/larger data spaces, risking index-out-of-bounds panics or storage corruption."
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
            status = "REJECTED_SOLANA_ACCOUNT_DATA".to_string();
        } else {
            status = "WARN_SOLANA_ACCOUNT_DATA".to_string();
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
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit(&Input {
            file_path: "lib.rs".into(),
            rust_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_with_size_check_passes() {
        let o = run(
            "fn process(account: &AccountInfo) { let data = account.try_borrow_data()?; let _ = data.len(); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn missing_size_check_flagged() {
        let o = run("fn handler(account: &AccountInfo) { let data = account.try_borrow_data()?; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SOLANA_ACCOUNT_DATA");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["handler"]);
    }

    #[test]
    fn no_account_info_is_secure() {
        let o = run("fn helper(x: u64) -> u64 { x + 1 }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
