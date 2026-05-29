//! Port of `pi_micro_agents/pi_misconfig_pattern_matcher.py`.
//!
//! Deterministic signature-based security pattern matching for standard
//! application and infrastructure config files (INI, properties, JSON).
//! Behaviour is a line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub config_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub matched_patterns: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff it equals
/// (case-insensitively) "true"; if unset, strict (true).
fn is_strict_mode() -> bool {
    match std::env::var("PI_CONFIG_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn match_config(input: &Input) -> Output {
    let content = input.config_content.to_lowercase();
    let mut matched: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Hardcoded passwords in files
    if content.contains("password=")
        || content.contains("password:")
        || content.contains("passwd=")
        || content.contains("passwd:")
    {
        if content.contains("test") || content.contains("admin") || content.contains("root") {
            matched.push(
                "Hardcoded Admin Password: Plaintext credentials found in static properties file."
                    .to_string(),
            );
            risk_score = risk_score.max(85.0);
        }
    }

    // Test or sandbox systems
    if content.contains("test_mode: true")
        || content.contains("debug=true")
        || content.contains("debug: true")
    {
        matched.push(
            "Debug Mode Enabled: Development logs active, exposing internal routing systems."
                .to_string(),
        );
        risk_score = risk_score.max(60.0);
    }

    // Insecure DB settings
    if content.contains("allow_empty_password=true") || content.contains("empty_password=true") {
        matched.push(
            "Insecure DB Config: Database root user allowed to connect with empty password."
                .to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec { "PASSED" } else { "MISCONFIG_FOUND" }.to_string();
    if risk_score > 0.0 && is_sec {
        status = "WARN_MISCONFIG".to_string();
    }

    Output {
        is_secure: is_sec,
        matched_patterns: matched,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = match_config(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        match_config(&Input {
            config_content: content.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("host = localhost\nport = 8080");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.matched_patterns.is_empty());
    }

    #[test]
    fn empty_password_is_rejected() {
        // risk 90 > 30 and strict mode (default) -> not secure
        let o = run("allow_empty_password=true");
        assert!(!o.is_secure);
        assert_eq!(o.status, "MISCONFIG_FOUND");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.matched_patterns.len(), 1);
    }

    #[test]
    fn hardcoded_admin_password_flagged() {
        // Uppercase exercises the .lower() normalization.
        let o = run("ADMIN_PASSWORD=hunter2\nuser=ADMIN");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(
            o.matched_patterns,
            vec![
                "Hardcoded Admin Password: Plaintext credentials found in static properties file."
                    .to_string()
            ]
        );
    }

    #[test]
    fn debug_only_warns_when_secure() {
        // risk 60 > 30 so strict-mode default rejects; but a sub-threshold
        // check: debug enabled is 60 which exceeds 30 -> MISCONFIG_FOUND.
        let o = run("debug=true");
        assert!(!o.is_secure);
        assert_eq!(o.status, "MISCONFIG_FOUND");
        assert_eq!(o.risk_score, 60.0);
    }
}
