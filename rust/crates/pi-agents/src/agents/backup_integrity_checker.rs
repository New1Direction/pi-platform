//! Port of `pi_micro_agents/pi_backup_integrity_checker.py`.
//!
//! Verifies multi-region backup replication, recovery checkpoints, and active
//! vault lock policies. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub backup_config: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff its value is
/// (case-insensitively) "true"; if unset, default to strict (true).
fn is_strict_mode() -> bool {
    match std::env::var("PI_BACKUP_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn check_backup(input: &Input) -> Output {
    let content = input.backup_config.to_lowercase();
    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Non-encrypted backups
    if content.contains("encryption: false")
        || content.contains("encryption: disabled")
        || content.contains("unencrypted")
    {
        issues.push(
            "Unencrypted Backups: Backed up assets are stored without standard encryption controls."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // Single region, no replication
    if content.contains("replication: false")
        || content.contains("replicate=false")
        || content.contains("replication: disabled")
    {
        issues.push(
            "Single Point of Failure: No cross-region or multi-zone replication configuration."
                .to_string(),
        );
        risk_score = risk_score.max(70.0);
    }

    // Insecure or missing retention configuration
    if content.contains("retention: 0")
        || content.contains("retention: 1d")
        || content.contains("retention: 1")
    {
        issues.push(
            "Short Retention Period: Backup assets are retained for less than a compliant lifecycle duration."
                .to_string(),
        );
        risk_score = risk_score.max(60.0);
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
    let out = check_backup(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cfg: &str) -> Output {
        check_backup(&Input {
            backup_config: cfg.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("encryption: true\nreplication: true\nretention: 30d");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn unencrypted_fails_compliance() {
        let o = run("encryption: false");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.issues.len(), 1);
    }

    #[test]
    fn short_retention_only_warns_when_below_threshold() {
        // retention: 1 -> risk 60.0 (> 30) so it fails under strict mode
        let o = run("retention: 1");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
    }
}
