//! Port of `pi_micro_agents/pi_structured_logging_enforcer.py`.
//!
//! Specialized linter enforcing structured/JSON logging across source code and
//! flagging plain `print(` statements. Behaviour is a line-for-line mirror of
//! the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub code_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub unstructured_statements: Vec<String>,
    pub compliance_score: f64,
    pub status: String,
}

/// Mirrors `re.compile(r"\bprint\s*\(")`. No lookaround/backrefs, so the Rust
/// `regex` crate handles it directly.
static PRINT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bprint\s*\(").unwrap());

pub fn enforce_structured_logging(input: &Input) -> Output {
    let content = &input.code_content;
    let mut findings: Vec<String> = Vec::new();
    let mut deductions: f64 = 0.0;

    // Scan for raw 'print(' statements
    for (i, line) in pyutil::splitlines(content).into_iter().enumerate() {
        let idx = i + 1;
        if PRINT_RE.is_match(line) && !pyutil::strip(line).starts_with('#') {
            findings.push(format!("Line {idx}: print used"));
            deductions += 15.0;
        }
    }

    let compliance_score = (100.0 - deductions).max(0.0);
    let is_secure = compliance_score >= 90.0;
    let status = if is_secure {
        "COMPLIANT".to_string()
    } else {
        "NON_COMPLIANT".to_string()
    };

    Output {
        is_secure,
        unstructured_statements: findings,
        compliance_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = enforce_structured_logging(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        enforce_structured_logging(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
        })
    }

    #[test]
    fn clean_code_is_compliant() {
        let o = run("logger.info('hello')\nlogger.debug('world')");
        assert!(o.is_secure);
        assert_eq!(o.status, "COMPLIANT");
        assert_eq!(o.compliance_score, 100.0);
        assert!(o.unstructured_statements.is_empty());
    }

    #[test]
    fn single_print_flagged() {
        let o = run("print('debug')");
        assert!(!o.is_secure);
        assert_eq!(o.status, "NON_COMPLIANT");
        assert_eq!(o.compliance_score, 85.0);
        assert_eq!(o.unstructured_statements, vec!["Line 1: print used"]);
    }

    #[test]
    fn commented_print_ignored() {
        // A `#`-prefixed line (after strip) is not flagged.
        let o = run("   # print('not a real print')\nlogger.info('ok')");
        assert!(o.is_secure);
        assert!(o.unstructured_statements.is_empty());
        assert_eq!(o.compliance_score, 100.0);
    }

    #[test]
    fn floor_at_zero() {
        // Many prints clamp the score at 0.0 (>6 findings).
        let code = "print(1)\nprint(2)\nprint(3)\nprint(4)\nprint(5)\nprint(6)\nprint(7)";
        let o = run(code);
        assert_eq!(o.compliance_score, 0.0);
        assert_eq!(o.unstructured_statements.len(), 7);
    }
}
