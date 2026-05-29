//! Port of `pi_micro_agents/pi_solidity_selfdestruct_code_erase_sentry.py`.
//!
//! Audits Solidity contracts for risky or deprecated `selfdestruct`/`suicide`
//! invocations (EIP-6780 / Cancun code-erase semantics). Behaviour is a
//! line-for-line mirror of the Python original.

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
    match std::env::var("PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Mirrors the Python `re.findall` pattern on line 44. Three capture groups:
//   group 1 -> the function name  [a-zA-Z0-9_]+
//   group 2 -> the argument list  (.*?)  (`.` does NOT match newlines, like Python)
//   group 3 -> the body           ([\s\S]*?) (matches any char including newlines)
// No lookaround/backreferences, so the Rust `regex` crate is byte-compatible.
static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

pub fn audit_selfdestruct_usage(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions
    for caps in FUNC_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) is captured by the Python pattern but unused in logic.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check for selfdestruct or suicide
        if body.contains("selfdestruct") || body.contains("suicide") {
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Function '{name}' contains 'selfdestruct' or 'suicide' operation. \
Under Cancun EVM specifications (EIP-6780), selfdestruct will only erase the contract's code/state \
if executed in the same transaction it was deployed. Otherwise, it only sends ether, leaving the bytecode intact, risking locked funds or upgrade path breakage."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_SELFDESTRUCT_CODE_ERASE".to_string();
        } else {
            status = "WARN_SELFDESTRUCT_CODE_ERASE".to_string();
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
    let out = audit_selfdestruct_usage(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_selfdestruct_usage(&Input {
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
    fn selfdestruct_flagged() {
        let o = run("contract C { function kill() public { selfdestruct(owner); } }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_SELFDESTRUCT_CODE_ERASE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["kill"]);
    }

    #[test]
    fn suicide_flagged() {
        let o = run("contract C { function destroy() public { suicide(owner); } }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["destroy"]);
    }
}
