//! Port of `pi_micro_agents/pi_solidity_erc20_safe_approve_auditor.py`.
//!
//! Audits Solidity contracts for deprecated/unsafe direct ERC20 `approve()`
//! patterns instead of SafeERC20 `safeApprove`. Behaviour is a line-for-line
//! mirror of the Python original.

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

// Python: re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// 3 capture groups -> (name, args, body). `.` does NOT match newline (no DOTALL),
// but [\s\S] explicitly matches everything including newlines for the body.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: re.findall(r'\b([a-zA-Z0-9_]+\.approve\s*\(.*?\))', body)
// 1 capture group; `.` does NOT match newline (no DOTALL).
static DIRECT_APPROVE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([a-zA-Z0-9_]+\.approve\s*\(.*?\))").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ERC20_SAFE_APPROVE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_safe_approve(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group 2 (args) is captured but not used in the Python logic.
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check for direct .approve call, e.g. token.approve(spender, amount).
        // Safe methods are safeApprove, safeIncreaseAllowance, etc.
        for cap in DIRECT_APPROVE_RE.captures_iter(body) {
            let call = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            // Flag if it doesn't utilize safeApprove.
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Function '{name}' calls direct external ERC20 approve method '{call}' instead of SafeERC20 'safeApprove'. \
Some tokens (like USDT) do not return a boolean value or have dynamic behavior, causing direct approve calls to fail silently or lock up allowance configurations."
            ));
            break;
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ERC20_SAFE_APPROVE".to_string();
        } else {
            status = "WARN_ERC20_SAFE_APPROVE".to_string();
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
    let out = audit_safe_approve(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_safe_approve(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn safe_approve_passes() {
        let o = run("function f() public { token.safeApprove(spender, amount); }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn direct_approve_flagged() {
        let o = run("function f() public { token.approve(spender, amount); }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ERC20_SAFE_APPROVE");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["f"]);
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
