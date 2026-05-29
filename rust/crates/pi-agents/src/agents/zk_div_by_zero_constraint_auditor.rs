//! Port of `pi_micro_agents/pi_zk_div_by_zero_constraint_auditor.py`.
//!
//! Audits Circom templates for division expressions that lack an explicit
//! non-zero divisor constraint. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub circom_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_signals: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_DIV_BY_ZERO_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// Python's `.` (in `.*?`) does NOT match newline by default; `[\s\S]` does.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\(([^\n]*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// re.finditer(r'([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)', body)
static DIV_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)").unwrap());

pub fn audit_div_by_zero(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for tcap in TEMPLATE_RE.captures_iter(code) {
        let tname = tcap.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = tcap.get(3).map(|m| m.as_str()).unwrap_or("");

        // Find any division statement, e.g. a / b
        for dcap in DIV_RE.captures_iter(body) {
            let divisor = dcap.get(2).map(|m| m.as_str()).unwrap_or("");

            // Check if divisor has non-zero assertions/constraints.
            // The divisor token is `[a-zA-Z0-9_]+`, hence already regex-safe,
            // but we escape it defensively to mirror Python's f-string insertion
            // (which for these tokens is a no-op).
            let div_escaped = regex::escape(divisor);
            // rf'{divisor}\s*!==?\s*0'
            let constraint_a = Regex::new(&format!(r"{}\s*!==?\s*0", div_escaped)).unwrap();
            // rf'assert\s*\(\s*{divisor}\s*!=?\s*0\s*\)'
            let constraint_b =
                Regex::new(&format!(r"assert\s*\(\s*{}\s*!=?\s*0\s*\)", div_escaped)).unwrap();

            let has_nonzero_constraint = constraint_a.is_match(body) || constraint_b.is_match(body);

            if !has_nonzero_constraint {
                vulnerable_signals.push(divisor.to_string());
                flagged_findings.push(format!(
                    "Template '{tname}': Division using divisor '{divisor}' \
lacks an explicit non-zero constraint. This could lead to arithmetic failure or malicious provers exploiting zero division."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_DIV_BY_ZERO".to_string();
        } else {
            status = "WARN_ZK_DIV_BY_ZERO".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_signals,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_div_by_zero(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_div_by_zero(&Input {
            file_path: "f.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn guarded_division_passes() {
        let o = run("template Bar() { c <== x / y; y !== 0; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn unguarded_division_flagged() {
        let o = run("template Foo(n) {\n  signal b;\n  b <== a / divisor;\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_DIV_BY_ZERO");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_signals, vec!["divisor"]);
    }

    #[test]
    fn assert_guard_passes() {
        // assert(y != 0) satisfies the second constraint regex.
        let o = run("template Baz() { c <== x / y; assert(y != 0); }");
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
