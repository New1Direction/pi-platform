//! Port of `pi_micro_agents/pi_solidity_undeclared_return_variable_sentry.py`.
//!
//! Audits Solidity contracts for named return variables declared in a function
//! signature's `returns (...)` clause that are never explicitly assigned or
//! returned in the body. Behaviour is a line-for-line mirror of the Python
//! original.

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

// Python:
//   re.finditer(
//     r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*?returns\s*\((.*?)\)\s*\{([\s\S]*?)\}',
//     code)
// No DOTALL on the whole pattern -> `.` does not match newline (matches Rust
// default). `[\s\S]` explicitly matches any char incl. newline.
static FUNC_RETURNS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*?returns\s*\((.*?)\)\s*\{([\s\S]*?)\}")
        .unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_undeclared_returns(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions with named return variables.
    // captures_iter mirrors re.finditer (non-overlapping, left-to-right).
    for caps in FUNC_RETURNS_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // group(2) (args) is captured by Python but never used.
        let returns_clause = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(4).map(|m| m.as_str()).unwrap_or("");

        // Splitting by comma to handle multiple returns.
        // Python str.split(",") keeps empty segments; Rust split(',') matches.
        for slot in returns_clause.split(',') {
            // Python: parts = slot.strip().split()
            // no-arg split() collapses whitespace runs and drops empties.
            let stripped = pyutil::strip(slot);
            let parts: Vec<&str> = stripped.split_whitespace().collect();
            if parts.len() >= 2 {
                // The last part is likely the variable name.
                // Python: var_name = parts[-1].strip()
                let var_name = pyutil::strip(parts[parts.len() - 1]);
                // Exclude keywords like memory, storage, calldata, payable.
                if !matches!(var_name, "memory" | "storage" | "calldata" | "payable") {
                    // Check if var_name is assigned anywhere in the body, or if
                    // there is a return statement containing var_name.
                    let escaped = regex::escape(var_name);
                    // Python: r'\b' + re.escape(var_name) + r'\b\s*[-+=\/]?='
                    let assigned_re =
                        Regex::new(&format!(r"\b{escaped}\b\s*[-+=/]?=")).unwrap();
                    // Python: r'\breturn\b\s+[^;]*?\b' + re.escape(var_name) + r'\b'
                    let returned_re =
                        Regex::new(&format!(r"\breturn\b\s+[^;]*?\b{escaped}\b")).unwrap();

                    let is_assigned = assigned_re.is_match(body);
                    let is_returned = returned_re.is_match(body);

                    if !is_assigned && !is_returned {
                        vulnerable_funcs.push(name.to_string());
                        flagged_findings.push(format!(
                            "Function '{name}' declares a named return slot '{var_name}' but never assigns or explicitly returns it. \
This will cause the function to return a default/zero value, which might trigger severe logic flaws or incorrect status results."
                        ));
                        break; // flag this function once
                    }
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
            status = "REJECTED_UNDECLARED_RETURN_VARIABLE".to_string();
        } else {
            status = "WARN_UNDECLARED_RETURN_VARIABLE".to_string();
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
    let out = audit_undeclared_returns(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_undeclared_returns(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn unassigned_named_return_flagged() {
        // 'value' is declared but never assigned or returned.
        let o = run("function getVal() public returns (uint256 value) { uint256 x = 1; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_UNDECLARED_RETURN_VARIABLE");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["getVal"]);
    }

    #[test]
    fn assigned_named_return_passes() {
        let o = run("function getVal() public returns (uint256 value) { value = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn explicit_return_passes() {
        let o = run("function getVal() public returns (uint256 value) { return value; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn unnamed_return_ignored() {
        // Only a type, no variable name -> parts < 2 -> not flagged.
        let o = run("function getVal() public returns (uint256) { uint256 x = 1; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
