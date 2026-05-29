//! Port of `pi_micro_agents/pi_solidity_external_contracts_return_check.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts to ensure that
//! low-level `call()`, `delegatecall()`, or `staticcall()` returns are verified.
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Matches `re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)`.
/// Three capture groups: (name, args, body). `.` does not match `\n` (no DOTALL
/// in Python and the regex crate default agrees); `[\s\S]` matches anything.
static FUNC_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap());

/// Matches `re.findall(r'(\b[a-zA-Z0-9_]+\.(?:call|delegatecall|staticcall)\b\s*\(.*?\))', body)`.
/// One capture group: the call expression.
static CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\b[a-zA-Z0-9_]+\.(?:call|delegatecall|staticcall)\b\s*\(.*?\))").unwrap()
});

#[derive(Debug, Deserialize)]
pub struct Input {
    /// Solidity source file path.
    pub file_path: String,
    /// Solidity source code content.
    pub solidity_code: String,
    /// Strictness level: STRICT, MEDIUM.
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    /// Indicates if contract external call returns are checked.
    pub is_secure: bool,
    /// Vulnerable function names.
    pub vulnerable_functions: Vec<String>,
    /// Detailed findings on external contract call returns.
    pub flagged_findings: Vec<String>,
    /// Risk score from 0.0 to 100.0.
    pub risk_score: f64,
    /// Status classification.
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_external_returns(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for fb in FUNC_BLOCK_RE.captures_iter(code) {
        let name = &fb[1];
        let _args = &fb[2];
        let body = fb[3].to_string();

        // Check for low level calls: .call, .delegatecall, .staticcall.
        let calls: Vec<String> = CALL_RE
            .captures_iter(&body)
            .map(|c| c[1].to_string())
            .collect();
        for call in &calls {
            // A safe call should capture its return value: e.g. (bool success, ) = ...
            // Find the full statement containing the call.
            let stmt_pattern = format!("([^;]*?{}[^;]*);", regex::escape(call));
            let stmt_re = Regex::new(&stmt_pattern).unwrap();
            if let Some(sm) = stmt_re.captures(&body) {
                let statement = &sm[1];
                // Check if 'success' or '=' is present before the call (mirrors
                // `"=" in statement and any(var in statement.split("=")[0] ...)`).
                let has_assignment = statement.contains('=')
                    && {
                        let prefix = statement.split('=').next().unwrap_or("");
                        ["success", "ok", "result", "status", "res"]
                            .iter()
                            .any(|var| prefix.contains(var))
                    };
                // Check if it's asserted: require(success) or if (success).
                let has_check = has_assignment
                    && ["require", "assert", "if", "revert"]
                        .iter()
                        .any(|kw| body.contains(kw));

                if !has_check {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' executes low-level external call '{call}' but does not explicitly check its return value. \
Unchecked call returns can cause transactions to fail silently or let attackers exploit failed execution states."
                    ));
                    break; // flag the function once
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_EXTERNAL_CONTRACTS_RETURN".to_string();
        } else {
            status = "WARN_EXTERNAL_CONTRACTS_RETURN".to_string();
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
    let out = audit_external_returns(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_external_returns(&Input {
            file_path: "f.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn unchecked_delegatecall_flagged() {
        let o = run("function exec(address t) public { t.delegatecall(data); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_EXTERNAL_CONTRACTS_RETURN");
        assert_eq!(o.vulnerable_functions, vec!["exec"]);
        assert_eq!(o.risk_score, 80.0);
    }

    #[test]
    fn checked_call_passes() {
        let o = run(
            "function exec(address t) public { (bool success, ) = t.call(data); require(success); }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn assigned_without_check_flagged() {
        let o = run("function exec(address t) public { (bool success, ) = t.call(data); }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["exec"]);
    }

    #[test]
    fn empty_and_nofunc_pass() {
        assert!(run("").is_secure);
        assert!(run("uint x = 5;").is_secure);
    }
}
