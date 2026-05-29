//! Port of `pi_micro_agents/pi_solidity_divide_before_multiply_auditor.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts to prevent
//! precision loss caused by division before multiplication. Behaviour is a
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

// Python: r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}'
// No DOTALL: `.` does not match `\n`. `[\s\S]` does match newlines.
// 3 capture groups -> captures_iter (mirrors re.findall returning tuples).
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: r'\b[a-zA-Z0-9_]+\s*/\s*[a-zA-Z0-9_]+\s*\*\s*[a-zA-Z0-9_]+\b'
static OPERATOR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9_]+\s*/\s*[a-zA-Z0-9_]+\s*\*\s*[a-zA-Z0-9_]+\b").unwrap());

// Python: r'\.div\s*\(.*?\)\s*\.mul\s*\(' -- no DOTALL, `.` excludes newline.
static SAFEMATH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.div\s*\(.*?\)\s*\.mul\s*\(").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_divide_multiply(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions: re.findall yields (name, args, body) tuples.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        // args (group 2) is captured but unused, mirroring the Python loop var.
        let _args = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        let has_operator_issue = OPERATOR_RE.is_match(body);
        let has_safemath_issue = SAFEMATH_RE.is_match(body);

        if has_operator_issue || has_safemath_issue {
            vulnerable_funcs.push(name.to_string());
            flagged_findings.push(format!(
                "Function '{name}' performs division before multiplication in a math expression. \
Solidity does not support floating point numbers; performing division first truncates the fractional part, leading to severe precision loss."
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DIVIDE_BEFORE_MULTIPLY".to_string();
        } else {
            status = "WARN_DIVIDE_BEFORE_MULTIPLY".to_string();
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
    let out = audit_divide_multiply(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_divide_multiply(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("function safe(uint a, uint b) public { return a * b / c; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn operator_divide_before_multiply_flagged() {
        let o = run("function bad(uint a) public { uint r = a / b * c; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DIVIDE_BEFORE_MULTIPLY");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_functions, vec!["bad"]);
    }

    #[test]
    fn safemath_div_then_mul_flagged() {
        let o = run("function calc(uint a) public { uint r = a.div(b).mul(c); }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_functions, vec!["calc"]);
        assert_eq!(o.risk_score, 70.0);
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
