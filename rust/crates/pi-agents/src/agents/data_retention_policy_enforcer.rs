//! Port of `pi_micro_agents/pi_data_retention_policy_enforcer.py`.
//!
//! Verifies automated data deletion schedules, purging PII records, and
//! enforcing minimal storage lifetimes. Behaviour is a line-for-line mirror of
//! the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub policy_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// it is strict only when the value equals (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_RETENTION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn enforce_retention(input: &Input) -> Output {
    let content = input.policy_content.to_lowercase();
    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Retaining data indefinitely
    if content.contains("retain: indefinite")
        || content.contains("delete: never")
        || content.contains("retention: unlimited")
    {
        issues.push(
            "Indefinite Data Retention: Configuration stores user records indefinitely without automated purge triggers."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    // Retention of PII without strict consent controls
    if content.contains("pii: retain") || content.contains("personal_data: save") {
        if content.contains("consent_check: false") || content.contains("consent: false") {
            issues.push(
                "Uncontrolled PII Retention: Sensitive personal identifiers stored without mandatory consent checks."
                    .to_string(),
            );
            risk_score = risk_score.max(90.0);
        }
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_COMPLIANCE".to_string();
    }

    Output {
        is_secure: is_sec,
        issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = enforce_retention(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        enforce_retention(&Input {
            policy_content: content.into(),
        })
    }

    #[test]
    fn clean_policy_passes() {
        let o = run("retention: 30d\ndelete: scheduled\npurge: enabled");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn indefinite_retention_flagged() {
        let o = run("retain: indefinite");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.issues.len(), 1);
    }

    #[test]
    fn pii_without_consent_flagged() {
        let o = run("pii: retain\nconsent: false");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    fn pii_with_consent_not_flagged() {
        // PII retention present but consent check is not false -> no issue.
        let o = run("pii: retain\nconsent_check: true");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
