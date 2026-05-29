//! Port of `pi_micro_agents/pi_llm_prompt_egress_leak_detector.py`.
//!
//! Audits egress payload strings (LLM prompts / generations) for private
//! details such as API keys, credit cards, and SSNs. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub prompt: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_LLM_PROMPT_EGRESS_LEAK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// leak_patterns, in insertion order (Python dict preserves insertion order).
// Each pattern is compiled with the `(?i)` inline flag to mirror `re.IGNORECASE`.
static LEAK_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "AWS API Key",
            Regex::new(r"(?i)AKIA[0-9A-Z]{16}").unwrap(),
        ),
        (
            "Private Key",
            Regex::new(r"(?i)-----BEGIN\s+PRIVATE\s+KEY-----").unwrap(),
        ),
        (
            "Generic Secret / Token",
            Regex::new(r"(?i)api[-_]?key|secret[-_]?token|bearer\s+[a-zA-Z0-9_\-\.]+").unwrap(),
        ),
        (
            "Credit Card",
            Regex::new(r"(?i)\b[3-6][0-9]{11,15}\b").unwrap(),
        ),
        (
            "Social Security Number",
            Regex::new(r"(?i)\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        ),
    ]
});

pub fn audit_egress_leak(input: &Input) -> Output {
    let prompt = &input.prompt;
    let mut flagged_findings: Vec<String> = Vec::new();

    let mut is_secure = true;
    for (name, pattern) in LEAK_PATTERNS.iter() {
        if pattern.is_match(prompt) {
            is_secure = false;
            flagged_findings.push(format!(
                "Egress leak detected: Content matches pattern for '{name}'."
            ));
        }
    }

    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_LLM_PROMPT_EGRESS_LEAK".to_string();
        } else {
            status = "WARN_LLM_PROMPT_EGRESS_LEAK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_egress_leak(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(prompt: &str) -> Output {
        audit_egress_leak(&Input {
            prompt: prompt.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_prompt_passes() {
        let o = run("Tell me a joke about cats.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn aws_key_flagged() {
        let o = run("here is a key AKIAIOSFODNN7EXAMPLE for you");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LLM_PROMPT_EGRESS_LEAK");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(
            o.flagged_findings,
            vec!["Egress leak detected: Content matches pattern for 'AWS API Key'.".to_string()]
        );
    }

    #[test]
    fn ssn_flagged() {
        let o = run("my ssn is 123-45-6789");
        assert!(!o.is_secure);
        assert!(o
            .flagged_findings
            .iter()
            .any(|f| f.contains("Social Security Number")));
    }
}
