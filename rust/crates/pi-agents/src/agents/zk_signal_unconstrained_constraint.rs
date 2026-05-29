//! Port of `pi_micro_agents/pi_zk_signal_unconstrained_constraint.py`.
//!
//! Audits Circom templates for signals assigned via `<--` or `-->` without an
//! active `===` constraint. Behaviour is a line-for-line mirror of the Python
//! original.

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
    match std::env::var("PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)
// 3 capture groups -> captures_iter. `.` (no DOTALL) does not match newlines in
// either Python or the Rust regex crate, so `(.*?)` behaves identically.
static TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// re.findall(r'([a-zA-Z0-9_]+)\s*(?:<--|-->)', body)
// 1 capture group -> captures_iter.
static ASSIGN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9_]+)\s*(?:<--|-->)").unwrap());

pub fn audit_unconstrained_signals(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // templates = re.findall(...) -> list of (tname, params, body) tuples.
    for caps in TEMPLATE_RE.captures_iter(code) {
        let tname = &caps[1];
        // params (caps[2]) is captured by Python but unused in the loop body.
        let body = &caps[3];

        // assignments = re.findall(r'([a-zA-Z0-9_]+)\s*(?:<--|-->)', body)
        for acaps in ASSIGN_RE.captures_iter(body) {
            let signal = &acaps[1];

            // if not re.search(rf'{signal}\s*===', body)
            //    and not re.search(rf'===\s*{signal}', body):
            // `signal` only contains [a-zA-Z0-9_], so it needs no escaping to be
            // interpolated into a pattern (matching Python's raw interpolation).
            let lhs = Regex::new(&format!(r"{}\s*===", signal)).unwrap();
            let rhs = Regex::new(&format!(r"===\s*{}", signal)).unwrap();

            if !lhs.is_match(body) && !rhs.is_match(body) {
                vulnerable_signals.push(signal.to_string());
                flagged_findings.push(format!(
                    "Template '{tname}': Signal '{signal}' is assigned values using non-constraining operators (<-- or -->) \
but lacks a corresponding quadratic constraint (===). This allows a prover to supply arbitrary witness values."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_SIGNAL_UNCONSTRAINED".to_string();
        } else {
            status = "WARN_ZK_SIGNAL_UNCONSTRAINED".to_string();
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
    let out = audit_unconstrained_signals(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_unconstrained_signals(&Input {
            file_path: "f.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn constrained_signal_passes() {
        let o = run("template T() { signal out; out <-- a * b; out === a * b; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    fn unconstrained_signal_flagged() {
        let o = run("template T() { signal out; out <-- a * b; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_SIGNAL_UNCONSTRAINED");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_signals, vec!["out"]);
    }

    #[test]
    fn no_template_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
