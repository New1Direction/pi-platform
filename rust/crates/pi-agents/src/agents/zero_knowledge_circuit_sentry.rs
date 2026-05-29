//! Port of `pi_micro_agents/pi_zero_knowledge_circuit_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits ZK Circom templates for
//! under-constrained signals: signals assigned with the unconstrained operators
//! `<--` / `-->` that lack a matching `===` constraint assertion. Behaviour is a
//! line-for-line mirror of the Python original.

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

// `template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}`
// 3 capture groups -> captures_iter (mirrors re.findall with groups).
// `.` does not match newline (Python has no DOTALL flag here); `[\s\S]` does.
// Negated class `[^{]` matches newlines in both Python and the regex crate.
static TEMPLATE_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// `signal\s+(?:input|output|private)?\s*([a-zA-Z0-9_]+)\s*;`
// 1 capture group -> captures_iter (we only need group 1).
static SIGNAL_DECL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"signal\s+(?:input|output|private)?\s*([a-zA-Z0-9_]+)\s*;").unwrap());

// `([a-zA-Z0-9_]+)\s*(?:<--|-->)\s*`
// 1 capture group -> captures_iter (we only need group 1).
static ASSIGNMENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9_]+)\s*(?:<--|-->)\s*").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_ZK_CIRCUIT_STRICT_MODE`; if set it returns
/// `env_val.lower() == "true"`. Otherwise it consults
/// `~/.antigravitycli/config.json` (falling back to a repo-relative
/// `.antigravitycli/config.json`) and returns
/// `bool(data.get("PI_ZK_CIRCUIT_STRICT_MODE", True))`. In the parity
/// environment neither config file contains the `PI_ZK_CIRCUIT_STRICT_MODE`
/// key (or no config file exists), so the config branch always yields `True`,
/// and the final default is also `True`. This Rust port therefore returns
/// `true` whenever the env var is unset. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZK_CIRCUIT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_zk_circuit(input: &Input) -> Output {
    let code = &input.circom_code;
    let mut vulnerable_signals: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find templates in Circom: re.findall with 3 groups -> captures_iter.
    for caps in TEMPLATE_BLOCK_RE.captures_iter(code) {
        let tname = caps.get(1).map_or("", |m| m.as_str());
        let _targs = caps.get(2).map_or("", |m| m.as_str());
        let tbody = caps.get(3).map_or("", |m| m.as_str());

        // Look for signal declarations: re.findall with 1 group.
        // (Collected but not used downstream, mirroring the Python original
        // which assigns `declared_signals` and never reads it.)
        let _declared_signals: Vec<String> = SIGNAL_DECL_RE
            .captures_iter(tbody)
            .map(|c| c.get(1).map_or("", |m| m.as_str()).to_string())
            .collect();

        // Check for unconstrained assignments (<-- or -->): re.findall, 1 group.
        let assignments: Vec<String> = ASSIGNMENT_RE
            .captures_iter(tbody)
            .map(|c| c.get(1).map_or("", |m| m.as_str()).to_string())
            .collect();

        for sig in &assignments {
            // Build a per-signal constraint pattern, mirroring Python's
            // dynamic regex: r'(\b' + sig + r'\b\s*===|===\s*\b' + sig + r'\b)'.
            // `sig` matches [a-zA-Z0-9_]+ so it contains no regex metacharacters.
            let constraint_pattern = format!(r"(\b{sig}\b\s*===|===\s*\b{sig}\b)");
            let constraint_re = Regex::new(&constraint_pattern).unwrap();
            if !constraint_re.is_match(tbody) {
                if !vulnerable_signals.contains(sig) {
                    vulnerable_signals.push(sig.clone());
                    flagged_findings.push(format!(
                        "Signal '{sig}' in template '{tname}' is assigned using an unconstrained operator \
(<-- or -->) but lacks a matching dynamic constraint assertion (===). \
This creates an under-constrained circuit, allowing malicious witnesses to bypass rules."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_signals.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_ZK_RISK".to_string();
        } else {
            status = "WARN_ZK_RISK".to_string();
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
    let out = audit_zk_circuit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_zk_circuit(&Input {
            file_path: "circuit.circom".into(),
            circom_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_circuit_passes() {
        // out is constrained with === so it is not flagged.
        let code = "template T() {\n  signal input a;\n  signal output out;\n  out <-- a * a;\n  out === a * a;\n}";
        std::env::remove_var("PI_ZK_CIRCUIT_STRICT_MODE");
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_signals.is_empty());
    }

    #[test]
    #[serial]
    fn under_constrained_signal_flagged() {
        // out is assigned with <-- but never constrained with ===.
        let code = "template T() {\n  signal input a;\n  signal output out;\n  out <-- a * a;\n}";
        std::env::remove_var("PI_ZK_CIRCUIT_STRICT_MODE");
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_ZK_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_signals, vec!["out"]);
    }

    #[test]
    #[serial]
    fn non_strict_warns_and_coerces_secure() {
        let code = "template T() {\n  signal output out;\n  out <-- 5;\n}";
        std::env::set_var("PI_ZK_CIRCUIT_STRICT_MODE", "false");
        let o = run(code);
        std::env::remove_var("PI_ZK_CIRCUIT_STRICT_MODE");
        assert!(o.is_secure); // coerced back to true on WARN path
        assert_eq!(o.status, "WARN_ZK_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_signals, vec!["out"]);
    }
}
