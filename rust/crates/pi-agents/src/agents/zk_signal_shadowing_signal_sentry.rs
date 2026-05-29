//! Port of `pi_micro_agents/pi_zk_signal_shadowing_signal_sentry.py`.
//!
//! Audits Circom source code for signal declarations that duplicate or shadow
//! outer definitions within the same template. Behaviour is a line-for-line
//! mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

// Python: r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}'
// 3 capture groups -> use captures_iter. `.` in the regex crate (like Python
// without DOTALL) does not match `\n`; `[\s\S]` explicitly matches everything
// including newlines, mirroring the Python pattern exactly.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: r'signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)'
// 1 capture group; non-capturing group is supported by the regex crate.
static SIGNAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_SIGNAL_SHADOWING_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_signal_shadowing(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = caps.get(1).map_or("", |m| m.as_str());
        // group 2 (params) is captured by Python but unused in the loop body.
        let body = caps.get(3).map_or("", |m| m.as_str());

        let mut seen_signals: HashSet<String> = HashSet::new();
        for scaps in SIGNAL_RE.captures_iter(body) {
            let sig = scaps.get(1).map_or("", |m| m.as_str());
            if seen_signals.contains(sig) {
                vulnerable_signals.push(sig.to_string());
                flagged_findings.push(format!(
                    "Template '{tname}': Signal '{sig}' is declared more than once, leading to potential variable shadowing and constraint bypassing."
                ));
            }
            seen_signals.insert(sig.to_string());
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_SIGNAL_SHADOWING".to_string();
        } else {
            status = "WARN_ZK_SIGNAL_SHADOWING".to_string();
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
    let out = audit_signal_shadowing(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_signal_shadowing(&Input {
            file_path: "main.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_template_passes() {
        let o = run("template Adder() { signal input a; signal input b; signal output c; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn duplicate_signal_flagged() {
        let o = run("template Bad() { signal input x; signal output x; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_SIGNAL_SHADOWING");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_signals, vec!["x"]);
    }

    #[test]
    fn empty_code_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
