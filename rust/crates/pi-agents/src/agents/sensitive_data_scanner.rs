//! Port of `pi_micro_agents/pi_sensitive_data_scanner.py`.
//!
//! Scans raw text for PII / sensitive data: Social Security Numbers, email
//! addresses, and credit-card-like number structures. Behaviour is a
//! line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub data_label: String,
    pub text_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub discovered_pii_elements: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// `re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\bssn\b", re.IGNORECASE)`
static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b\d{3}-\d{2}-\d{4}\b|\bssn\b").unwrap());

// `re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")`
// NOTE: the `|` inside `[A-Z|a-z]` is a literal `|` in a character class,
// identical to Python's behaviour.
static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap());

// `re.compile(r"\b(?:\d[ -]*?){13,16}\b")` — lazy inner quantifier.
static CC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap());

// `re.sub(r"[ -]", "", ...)` — strip spaces and dashes.
static CC_STRIP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[ -]").unwrap());

pub fn scan_sensitive_data(input: &Input) -> Output {
    let content = &input.text_content;
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Scan for Social Security Number (SSN)
    if SSN_RE.is_match(content) {
        findings.push("SSN Leak".to_string());
        risk_score += 50.0;
    }

    // Scan for Email addresses
    if EMAIL_RE.is_match(content) {
        findings.push("Email Leak".to_string());
        risk_score += 20.0;
    }

    // Scan for credit card structures
    if let Some(m) = CC_RE.find(content) {
        // Exclude standard phone number length formats if possible or verify
        let cleaned_cc = CC_STRIP_RE.replace_all(m.as_str(), "").to_string();
        let len = cleaned_cc.chars().count();
        if (len == 15 || len == 16) && !cleaned_cc.starts_with("000") {
            findings.push("Credit Card Leak".to_string());
            risk_score += 45.0;
        }
    }

    if risk_score > 100.0 {
        risk_score = 100.0;
    }
    let is_secure = risk_score < 40.0;
    let status = if !is_secure {
        "FLAGGED".to_string()
    } else {
        "PASSED".to_string()
    };

    Output {
        is_secure,
        discovered_pii_elements: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_sensitive_data(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Output {
        scan_sensitive_data(&Input {
            data_label: "label".into(),
            text_content: text.into(),
        })
    }

    #[test]
    fn clean_text_passes() {
        let o = run("hello world, nothing to see here");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.discovered_pii_elements.is_empty());
    }

    #[test]
    fn ssn_keyword_flagged() {
        let o = run("the SSN field is missing");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FLAGGED");
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.discovered_pii_elements, vec!["SSN Leak"]);
    }

    #[test]
    fn ssn_pattern_flagged() {
        let o = run("my ssn is 123-45-6789 ok");
        assert!(!o.is_secure);
        // Both the digit pattern and the word would match; one finding.
        assert_eq!(o.discovered_pii_elements, vec!["SSN Leak"]);
        assert_eq!(o.risk_score, 50.0);
    }

    #[test]
    fn email_alone_passes_threshold() {
        // Email alone is 20.0 -> below 40.0 -> secure/PASSED.
        let o = run("contact me at john.doe@example.com please");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 20.0);
        assert_eq!(o.discovered_pii_elements, vec!["Email Leak"]);
    }

    #[test]
    fn credit_card_flagged() {
        // 16-digit number -> Credit Card Leak (45.0).
        let o = run("card 4111 1111 1111 1111 on file");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FLAGGED");
        assert_eq!(o.discovered_pii_elements, vec!["Credit Card Leak"]);
        assert_eq!(o.risk_score, 45.0);
    }
}
