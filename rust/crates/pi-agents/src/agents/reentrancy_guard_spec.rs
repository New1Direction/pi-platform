//! Port of `pi_micro_agents/pi_reentrancy_guard_spec.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for
//! custom/incorrect reentrancy protections and CEI (Checks-Effects-Interactions)
//! violations. Behaviour is a line-for-line mirror of the Python original.

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

// Regexes mirroring the Python originals.
//
// Python: r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}'
// No DOTALL, so `.` (in `.*?`) does NOT match newlines — same as Rust default.
// `[\s\S]*?` matches everything incl. newlines. 3 capture groups, re.findall.
static FUNC_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}").unwrap()
});

// Python: r'\.(call|transfer|send)\s*\('  -- re.search (we need the full match)
static EXTERNAL_CALL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(call|transfer|send)\s*\(").unwrap());

// Python: r'([a-zA-Z0-9_]+)\s*(\+=|-=|=)\s*'  -- re.search (we need the full match)
static STATE_WRITE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-zA-Z0-9_]+)\s*(\+=|-=|=)\s*").unwrap());

// Python: r'\bnonReentrant\b'  -- re.search
static NON_REENTRANT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bnonReentrant\b").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is (case-insensitively) "true" controls it. When the env var is unset the
/// Python code consults a config file and ultimately defaults to `True`; this
/// port defaults to strict (`true`) in that case. See module deviations.
fn is_strict_mode() -> bool {
    match std::env::var("PI_REENTRANCY_SPEC_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_reentrancy_spec(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all functions. re.findall with 3 groups -> captures_iter yielding
    // (name, args, body). `args` is captured but unused, mirroring Python.
    for caps in FUNC_BLOCK_RE.captures_iter(code) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let body = caps.get(3).map_or("", |m| m.as_str());

        // Mode 1: Check for external call before state write
        let external_call_match = EXTERNAL_CALL_RE.find(body);
        let state_write_match = STATE_WRITE_RE.find(body);

        if let (Some(call_m), Some(write_m)) = (external_call_match, state_write_match) {
            // Find positions to see if state write happens after external call.
            // Python uses body.find(<group(0)>) which returns the position of
            // the FIRST occurrence of the matched substring (not necessarily
            // the match's own position). Mirror that exactly via str::find.
            let call_pos = body.find(call_m.as_str()).unwrap();
            let write_pos = body.find(write_m.as_str()).unwrap();

            if write_pos > call_pos {
                // Check if it has a nonReentrant modifier.
                // Python: "nonReentrant" in code or re.search(r'\bnonReentrant\b', body)
                let has_modifier =
                    code.contains("nonReentrant") || NON_REENTRANT_RE.find(body).is_some();
                if !has_modifier {
                    vulnerable_funcs.push(name.to_string());
                    flagged_findings.push(format!(
                        "Function '{name}' performs an external call before a state-changing operation \
and is missing the 'nonReentrant' modifier. This violates the Checks-Effects-Interactions (CEI) pattern."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_REENTRANCY_RISK".to_string();
        } else {
            status = "WARN_REENTRANCY_RISK".to_string();
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
    let out = audit_reentrancy_spec(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_reentrancy_spec(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn secure_code_passes() {
        std::env::remove_var("PI_REENTRANCY_SPEC_STRICT_MODE");
        // No external call before state write -> secure.
        let o = run("function deposit() public { balance += msg.value; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    #[serial]
    fn vulnerable_call_before_write_rejected_strict() {
        std::env::set_var("PI_REENTRANCY_SPEC_STRICT_MODE", "true");
        // .call(...) appears before the `balance = 0` state write, no modifier.
        let o = run("function withdraw() public { msg.sender.call(\"\"); balance = 0; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_REENTRANCY_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
        std::env::remove_var("PI_REENTRANCY_SPEC_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn vulnerable_non_strict_warns_and_coerces_secure() {
        std::env::set_var("PI_REENTRANCY_SPEC_STRICT_MODE", "false");
        let o = run("function withdraw() public { msg.sender.call(\"\"); balance = 0; }");
        assert!(o.is_secure); // coerced back to true in non-strict mode
        assert_eq!(o.status, "WARN_REENTRANCY_RISK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
        std::env::remove_var("PI_REENTRANCY_SPEC_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn non_reentrant_modifier_is_safe() {
        std::env::remove_var("PI_REENTRANCY_SPEC_STRICT_MODE");
        let o = run(
            "function withdraw() public nonReentrant { msg.sender.call(\"\"); balance = 0; }",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_functions.is_empty());
    }
}
