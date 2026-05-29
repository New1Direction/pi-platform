//! Port of `pi_micro_agents/pi_prompt_leak_buster.py`.
//!
//! Zero-Trust data-privacy egress leak scanner. Audits outgoing text for
//! hardcoded credentials, PII leakage, and system-prompt instruction leakage.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub risk_score: f64,
    pub status: String,
    pub flagged_leaks: Vec<String>,
}

// `pyutil` is imported for parity with sibling ports; not all helpers are used
// by every agent. Silence the unused-import lint without dropping the import.
#[allow(unused_imports)]
use pyutil as _pyutil_marker;

// --- Section A: Credential / Private Key Leaks (re.IGNORECASE) ---
static SECRET_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r#"(?i)(?:api_key|apikey|api-key)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]"#)
                .unwrap(),
            "hardcoded API key",
        ),
        (
            Regex::new(
                r#"(?i)(?:private_key|privatekey)\s*[:=]\s*['"](?:0x)?[a-fA-F0-9]{64,}['"]"#,
            )
            .unwrap(),
            "hardcoded private key hex signature",
        ),
        (
            Regex::new(
                r#"(?i)(?:secret|client_secret|client-secret)\s*[:=]\s*['"][a-zA-Z0-9_\-+=/]{30,}['"]"#,
            )
            .unwrap(),
            "hardcoded client secret token",
        ),
    ]
});

// --- Section B: Personally Identifiable Information (case-sensitive) ---
static PII_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"#).unwrap(),
            "Personally Identifiable Information (PII) email leak",
        ),
        (
            Regex::new(r#"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"#).unwrap(),
            "Personally Identifiable Information (PII) phone leak",
        ),
    ]
});

// --- Section C: System Prompt / Instruction Leakage (re.IGNORECASE) ---
static SYSTEM_LEAK_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(
                r#"(?i)\byou\s+are\s+a\s+(?:helpful|powerful|agentic|safety|specialized|assistant)\b"#,
            )
            .unwrap(),
            "system prompt role instruction leakage",
        ),
        (
            Regex::new(r#"(?i)\bignore\s+previous\s+instructions\b"#).unwrap(),
            "system prompt override leak pattern",
        ),
        (
            Regex::new(r#"(?i)\bcore\s+system\s+(?:instructions|guidelines|prompt)\b"#).unwrap(),
            "system prompt structural keyword leak",
        ),
    ]
});

/// Mirrors `is_strict_mode()`.
///
/// Python: if env var `PI_LEAK_STRICT_MODE` is set, returns whether it equals
/// (case-insensitively) "true"; otherwise it consults a config JSON file and
/// finally defaults to True. We mirror the env-var branch and the default-True
/// fallback (see deviations re: the config-file branch).
fn is_strict_mode() -> bool {
    match std::env::var("PI_LEAK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `detect_leak_anomalies(text)`: returns `(max_risk, violations)`.
fn detect_leak_anomalies(text: &str) -> (f64, Vec<String>) {
    let mut violations: Vec<String> = Vec::new();
    let mut max_risk = 0.0_f64;
    if text.is_empty() {
        return (0.0, Vec::new());
    }

    // A. Credential / Private Key Leaks
    for (pat, desc) in SECRET_PATTERNS.iter() {
        if pat.is_match(text) {
            violations.push(format!("potential leak of secret information: {desc}"));
            max_risk = max_risk.max(95.0);
        }
    }

    // B. Personally Identifiable Information (PII)
    for (pat, desc) in PII_PATTERNS.iter() {
        if pat.is_match(text) {
            violations.push((*desc).to_string());
            max_risk = max_risk.max(80.0);
        }
    }

    // C. System Prompt / Instruction Leakage
    for (pat, desc) in SYSTEM_LEAK_PATTERNS.iter() {
        if pat.is_match(text) {
            violations.push((*desc).to_string());
            max_risk = max_risk.max(85.0);
        }
    }

    (max_risk, violations)
}

/// Mirrors `PiPromptLeakBuster.scan_text`.
pub fn scan_text(input: &Input) -> Output {
    let (risk, violations) = detect_leak_anomalies(&input.text);

    let is_strict = is_strict_mode();
    let mut is_secure = true;
    let mut status = "PASSED".to_string();

    if risk >= 80.0 {
        if is_strict {
            is_secure = false;
            status = "REJECTED_LEAK".to_string();
        } else {
            status = "WARN_LEAK".to_string();
        }
    } else if risk >= 70.0 {
        status = "WARN_LEAK".to_string();
    }

    Output {
        is_secure,
        risk_score: risk,
        status,
        flagged_leaks: violations,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_text(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(text: &str) -> Output {
        scan_text(&Input { text: text.into() })
    }

    #[test]
    #[serial]
    fn clean_text_passes() {
        std::env::remove_var("PI_LEAK_STRICT_MODE");
        let o = run("This is a perfectly ordinary message about lunch.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_leaks.is_empty());
    }

    #[test]
    #[serial]
    fn secret_leak_rejected_in_strict_mode() {
        std::env::set_var("PI_LEAK_STRICT_MODE", "true");
        let o = run("config: api_key = \"abcdef0123456789ABCDEF_secret\"");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LEAK");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(
            o.flagged_leaks,
            vec!["potential leak of secret information: hardcoded API key"]
        );
        std::env::remove_var("PI_LEAK_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn pii_email_warns_in_non_strict_mode() {
        std::env::set_var("PI_LEAK_STRICT_MODE", "false");
        let o = run("contact me at john.doe@example.com please");
        // risk 80 -> WARN in non-strict, is_secure stays true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_LEAK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(
            o.flagged_leaks,
            vec!["Personally Identifiable Information (PII) email leak"]
        );
        std::env::remove_var("PI_LEAK_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn empty_text_passes() {
        std::env::remove_var("PI_LEAK_STRICT_MODE");
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_leaks.is_empty());
    }
}
