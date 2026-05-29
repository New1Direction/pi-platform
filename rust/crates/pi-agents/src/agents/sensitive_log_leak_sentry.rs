//! Port of `pi_micro_agents/pi_sensitive_log_leak_sentry.py`.
//!
//! Scans raw log content for exposed passwords, secrets/tokens, and private key
//! blocks. Behaviour is a line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub log_file_path: String,
    pub log_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_leaks: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

pub fn audit_log_leaks(input: &Input) -> Output {
    let content = &input.log_content;
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    let lower = content.to_lowercase();

    // Scan for password leaks
    if lower.contains("password") {
        findings.push("password leak".to_string());
        risk_score += 40.0;
    }

    // Scan for secret key or token exposures
    if ["secret", "api_key", "token", "private_key"]
        .iter()
        .any(|tok| lower.contains(tok))
    {
        findings.push("token or secret exposure in log line".to_string());
        risk_score += 45.0;
    }

    // Scan for standard private key tags
    if lower.contains("begin private key") {
        findings.push("private key block leak".to_string());
        risk_score += 50.0;
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if !is_secure { "FLAGGED" } else { "PASSED" }.to_string();

    Output {
        is_secure,
        flagged_leaks: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_log_leaks(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        audit_log_leaks(&Input {
            log_file_path: "app.log".into(),
            log_content: content.into(),
        })
    }

    #[test]
    fn clean_log_passes() {
        let o = run("INFO: request handled in 12ms");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_leaks.is_empty());
    }

    #[test]
    fn password_leak_flagged() {
        let o = run("user logged in with PASSWORD=hunter2");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FLAGGED");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(o.flagged_leaks, vec!["password leak"]);
    }

    #[test]
    fn all_leaks_caps_at_100() {
        let o = run("password and api_key and BEGIN PRIVATE KEY block");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FLAGGED");
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(
            o.flagged_leaks,
            vec![
                "password leak",
                "token or secret exposure in log line",
                "private key block leak"
            ]
        );
    }
}
