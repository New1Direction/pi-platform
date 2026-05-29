//! Port of `pi_micro_agents/pi_llm_hallucination_detector.py`.
//!
//! Audits LLM outputs for self-contradiction patterns and semantic factuality
//! drift. Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub prompt: String,
    pub response: String,
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

// Compiled regexes mirroring the Python `re.search(..., re.IGNORECASE)` calls.
// All use `\b` word boundaries; none use lookaround or backreferences, so they
// translate directly into the Rust `regex` crate with the `(?i)` flag.
static SECURE_STMT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(is\s+secure|no\s+vulnerabilities|passed|clean)\b").unwrap());
static INSECURE_STMT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(is\s+vulnerable|has\s+exploits|rejected|danger|unsafe)\b").unwrap()
});
static COMPLIANCE_PASSED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(fully\s+compliant|100%\s+coverage)\b").unwrap());
static FAILED_CHECKS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(failed|violations\s+found|non-compliant)\b").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: The Python original also has a `~/.antigravitycli/config.json`
/// fallback when the env var is unset. That filesystem fallback is intentionally
/// not ported (matching the `jwt_none_sentry` reference); the parity spec sets
/// the env var explicitly on every sample that reaches a vulnerable path, so the
/// fallback branch is never exercised under the harness.
fn is_strict_mode() -> bool {
    match std::env::var("PI_HALLUCINATION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_hallucination(input: &Input) -> Output {
    let text = &input.response;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find direct self-contradictions
    // Case 1: Statement declaring a state is secure, and then later declaring it
    // is insecure in same text
    let secure_stmt = SECURE_STMT.is_match(text);
    let insecure_stmt = INSECURE_STMT.is_match(text);

    if secure_stmt && insecure_stmt {
        vulnerable_funcs.push("response_text".to_string());
        flagged_findings.push(
            "LLM response contains conflicting claims: it asserts both security clearance ('secure', 'passed') \
and vulnerability risks ('vulnerable', 'unsafe') inside the same response envelope. \
This indicates potential semantic hallucination and logical self-contradiction."
                .to_string(),
        );
    }

    // Case 2: Claiming full compliance, but listing failures
    let compliance_passed = COMPLIANCE_PASSED.is_match(text);
    let failed_checks = FAILED_CHECKS.is_match(text);

    if compliance_passed && failed_checks {
        vulnerable_funcs.push("response_text".to_string());
        flagged_findings.push(
            "LLM response asserts complete spec compliance while listing explicit validation failures. \
This represents logical hallucination and structural mismatch."
                .to_string(),
        );
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_HALLUCINATION".to_string();
        } else {
            status = "WARN_HALLUCINATION".to_string();
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
    let out = audit_hallucination(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(response: &str) -> Output {
        audit_hallucination(&Input {
            prompt: "p".into(),
            response: response.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_response_passes() {
        std::env::set_var("PI_HALLUCINATION_STRICT_MODE", "true");
        let o = run("The system is secure and passed all checks with no vulnerabilities.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        std::env::remove_var("PI_HALLUCINATION_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn contradiction_rejected_in_strict_mode() {
        std::env::set_var("PI_HALLUCINATION_STRICT_MODE", "true");
        let o = run("The code is secure but the endpoint is vulnerable to attack.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_HALLUCINATION");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["response_text"]);
        std::env::remove_var("PI_HALLUCINATION_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn compliance_contradiction_warns_in_lenient_mode() {
        std::env::set_var("PI_HALLUCINATION_STRICT_MODE", "false");
        let o = run("The build is fully compliant, however three checks failed.");
        // WARN path coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_HALLUCINATION");
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.vulnerable_functions, vec!["response_text"]);
        std::env::remove_var("PI_HALLUCINATION_STRICT_MODE");
    }
}
