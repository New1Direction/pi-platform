//! Port of `pi_micro_agents/pi_solidity_owner_timelock_sentry.py`.
//!
//! Audits Solidity contracts to ensure administrative `onlyOwner` /
//! `onlyRole` privilege functions are protected by a timelock mechanism.
//! Behaviour is a line-for-line mirror of the Python original.

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
    match std::env::var("PI_OWNER_TIMELOCK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// No DOTALL flag, so `.` does not match '\n' (same default in the Rust regex crate).
// `[\s\S]` explicitly matches any char including newlines.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

pub fn audit_owner_timelock(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Check if contract mentions timelock or delay in any variable/function/comment
    let code_lower = code.to_lowercase();
    let has_timelock_mechanism = ["timelock", "delay", "min_delay", "queuedtransactions"]
        .iter()
        .any(|kw| code_lower.contains(kw));

    // Find all functions.
    // findall with 3 groups -> captures_iter, collecting (name, args, body).
    let func_blocks: Vec<(String, String, String)> = FUNC_BLOCK_RE
        .captures_iter(code)
        .map(|c| {
            (
                c.get(1).map_or("", |m| m.as_str()).to_string(),
                c.get(2).map_or("", |m| m.as_str()).to_string(),
                c.get(3).map_or("", |m| m.as_str()).to_string(),
            )
        })
        .collect();

    for (name, _args, _body) in &func_blocks {
        // Check if this function is onlyOwner or restricted.
        // Python: re.search(r'\bfunction\s+' + name + r'\s*\(.*?\)[^{]*?\bonlyOwner\b', code)
        // `name` matches [a-zA-Z0-9_]+ so it contains no regex-special chars and
        // can be embedded directly (mirrors the Python string concatenation).
        let pattern = format!(
            r"\bfunction\s+{}\s*\(.*?\)[^{{]*?\bonlyOwner\b",
            name
        );
        let admin_re = Regex::new(&pattern).unwrap();
        let is_admin_action = code.contains("onlyOwner") && admin_re.is_match(code);

        if is_admin_action && !has_timelock_mechanism {
            // Extra check: excludes standard view or configuration functions that are low risk
            let name_lower = name.to_lowercase();
            let is_low_risk = ["get", "view", "is", "renounce"]
                .iter()
                .any(|kw| name_lower.contains(kw));
            if !is_low_risk {
                vulnerable_funcs.push(name.clone());
                flagged_findings.push(format!(
                    "Administrative function '{name}' has 'onlyOwner' modifier but the contract lacks a timelock mechanism. \
Without a timelock, compromised admin keys can immediately drain funds or alter critical parameters without giving users time to withdraw."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_OWNER_TIMELOCK".to_string();
        } else {
            status = "WARN_OWNER_TIMELOCK".to_string();
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
    let out = audit_owner_timelock(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_owner_timelock(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn vulnerable_owner_function_flagged() {
        let code = "function withdraw(uint256 amount) public onlyOwner { balance -= amount; }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_OWNER_TIMELOCK");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
    }

    #[test]
    fn timelock_mechanism_makes_secure() {
        let code = "uint256 public minDelay; function withdraw(uint256 amount) public onlyOwner { delay(); }";
        // contains "delay" -> has_timelock_mechanism true -> no vuln
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn low_risk_getter_not_flagged() {
        let code = "function getBalance() public onlyOwner { return balance; }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
