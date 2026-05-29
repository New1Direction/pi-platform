//! Port of `pi_micro_agents/pi_audit_log_tamper_detector.py`.
//!
//! Scans system logs for sequence gaps, deletion queries, or audit record
//! modifications by unauthorized actors. Behaviour is a line-for-line mirror of
//! the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub log_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub anomalies: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_LOG_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn detect_tampering(input: &Input) -> Output {
    let content = input.log_content.to_lowercase();
    let mut anomalies: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Gap sequences / Missing indices
    if content.contains("gap detected")
        || content.contains("missing log sequence")
        || content.contains("sequence mismatch")
    {
        anomalies.push(
            "Audit Log Gap: System detected sequence ID discrepancies in consecutive events."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    // Clear or truncate log indicators
    if content.contains("rm -rf")
        || content.contains("clear logs")
        || content.contains("truncate table")
        || content.contains("log deleted")
    {
        anomalies.push(
            "Destructive Action: Administrative system commands executed to clear or truncate logs."
                .to_string(),
        );
        risk_score = risk_score.max(95.0);
    }

    // Deletion by unauthorized user
    if content.contains("delete") && content.contains("anonymous") {
        anomalies.push(
            "Unauthorized Log Deletion: Anonymous or guest role attempted delete/purge operations."
                .to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "ANOMALIES_DETECTED".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_ANOMALIES".to_string();
    }

    Output {
        is_secure: is_sec,
        anomalies,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = detect_tampering(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        detect_tampering(&Input {
            log_content: content.into(),
        })
    }

    #[test]
    fn clean_log_passes() {
        let o = run("INFO user logged in successfully");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.anomalies.is_empty());
    }

    #[test]
    fn destructive_action_flagged() {
        let o = run("admin ran rm -rf /var/log to clear logs");
        assert!(!o.is_secure);
        assert_eq!(o.status, "ANOMALIES_DETECTED");
        assert_eq!(o.risk_score, 95.0);
    }

    #[test]
    fn anonymous_delete_flagged() {
        let o = run("ANONYMOUS user attempted DELETE on audit table");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.status, "ANOMALIES_DETECTED");
    }
}
