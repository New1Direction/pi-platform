//! Port of `pi_micro_agents/pi_solidity_proxy_call_target_check.py`.
//!
//! Audits upgradeable proxy contracts to ensure `delegatecall` targets are
//! validated (whitelist / storage slot) rather than taken from arbitrary
//! user-supplied function arguments. Behaviour is a line-for-line mirror of the
//! Python original.

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
    match std::env::var("PI_PROXY_CALL_TARGET_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`
// Note: in both Python (no DOTALL) and the Rust regex crate, `.` does not match a
// newline by default, so `(.*?)` will not cross line boundaries. `[\s\S]*?` does.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

/// Mirror of Python `arg.strip().split()` (no-arg `split`): splits on runs of
/// ASCII/Unicode whitespace, discarding empty tokens. We use `split_whitespace`,
/// which has the same effect for the inputs this agent sees.
fn whitespace_split(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

pub fn audit_proxy_target(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check for delegatecall usage
        if body.contains("delegatecall") {
            // Look for delegatecall(..., target, ...) inside assembly or target.delegatecall(...)
            // Check if the target parameter is passed as a function argument
            let mut is_arg_target = false;
            // arg_names = [arg.strip().split()[-1] for arg in args.split(",") if len(arg.strip().split()) >= 2]
            let mut arg_names: Vec<&str> = Vec::new();
            for arg in args.split(',') {
                let toks = whitespace_split(arg);
                if toks.len() >= 2 {
                    arg_names.push(*toks.last().unwrap());
                }
            }

            // Check if delegatecall uses any function argument directly as the target
            for arg_name in &arg_names {
                let escaped = regex::escape(arg_name);
                // re.search(r'\bdelegatecall\s*\([^)]*?\b' + escaped + r'\b', body)
                let re1 =
                    Regex::new(&format!(r"\bdelegatecall\s*\([^)]*?\b{}\b", escaped)).unwrap();
                // re.search(r'\b' + escaped + r'\.delegatecall\b', body)
                let re2 = Regex::new(&format!(r"\b{}\.delegatecall\b", escaped)).unwrap();
                if re1.is_match(body) || re2.is_match(body) {
                    is_arg_target = true;
                    break;
                }
            }

            // If the target is an argument, verify it has a whitelist or mapping check
            if is_arg_target {
                let has_whitelist_check = ["whitelist", "isTarget", "isWhitelisted", "require", "assert"]
                    .iter()
                    .any(|kw| body.contains(kw));
                if !has_whitelist_check {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' performs a delegatecall where the target is a user-supplied parameter, but no whitelist validation was found. \
This allows an attacker to pass a malicious contract address as the target, seizing complete administrative control of the proxy storage state."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_PROXY_CALL_TARGET".to_string();
        } else {
            status = "WARN_PROXY_CALL_TARGET".to_string();
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
    let out = audit_proxy_target(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_proxy_target(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn arg_target_without_whitelist_is_vulnerable() {
        let code = "contract P { function upgrade(address target) public { target.delegatecall(data); } }";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PROXY_CALL_TARGET");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_functions, vec!["upgrade"]);
    }

    #[test]
    fn arg_target_with_require_is_safe() {
        let code = "contract P { function upgrade(address target) public { require(whitelist[target]); target.delegatecall(data); } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn no_delegatecall_is_safe() {
        let code = "contract P { function noop(uint256 x) public { uint y = x; } }";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
