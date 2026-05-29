//! Port of `pi_micro_agents/pi_secrets_manager_completeness_checker.py`.
//!
//! Verifies that secrets vaults enforce automated rotation limits, explicit IAM
//! permission boundaries, and audit logging. Behaviour is a line-for-line mirror
//! of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub vault_config: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub gaps: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_VAULT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Python `max(a, b)` for floats; used to replicate `risk_score = max(risk_score, X)`.
fn fmax(a: f64, b: f64) -> f64 {
    if a >= b {
        a
    } else {
        b
    }
}

pub fn check_vault_config(input: &Input) -> Output {
    let content = input.vault_config.to_lowercase();
    let mut gaps: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Missing rotation settings
    if content.contains("rotation: false")
        || content.contains("rotation: disabled")
        || content.contains("enable_rotation = false")
    {
        gaps.push(
            "Missing Auto-Rotation: Secret assets do not rotate automatically, raising breach lifecycle risk."
                .to_string(),
        );
        risk_score = fmax(risk_score, 70.0);
    }

    // Overly broad access policy
    if content.contains("policy: *")
        || content.contains("allow all policies")
        || content.contains("\"policy\": \"*\"")
    {
        gaps.push(
            "Permissive Access Policies: Wildcard policies allow unauthorized clients to pull arbitrary credentials."
                .to_string(),
        );
        risk_score = fmax(risk_score, 85.0);
    }

    // Missing KMS / KMS key default checks
    if content.contains("kms_key: default") || content.contains("default encryption key") {
        gaps.push(
            "Default Cryptographic Key: Default cloud provider keys are used rather than custom CMKs."
                .to_string(),
        );
        risk_score = fmax(risk_score, 50.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_VAULT_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_VAULT".to_string();
    }

    Output {
        is_secure: is_sec,
        gaps,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_vault_config(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cfg: &str) -> Output {
        check_vault_config(&Input {
            vault_config: cfg.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("rotation: true\npolicy: scoped\nkms_key: custom-cmk");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.gaps.is_empty());
    }

    #[test]
    fn wildcard_policy_fails_in_strict_mode() {
        // Ensure strict mode (default when env unset). Avoid env mutation races by
        // relying on the default-strict path.
        std::env::remove_var("PI_VAULT_STRICT_MODE");
        let o = run("policy: *");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_VAULT_COMPLIANCE");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.gaps.len(), 1);
    }

    #[test]
    fn default_kms_key_warns_below_threshold() {
        std::env::remove_var("PI_VAULT_STRICT_MODE");
        // risk_score 50.0 > 30.0 -> fails in strict mode.
        let o = run("kms_key: default");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.status, "FAILED_VAULT_COMPLIANCE");
    }

    #[test]
    fn rotation_disabled_uppercase_is_lowercased() {
        std::env::remove_var("PI_VAULT_STRICT_MODE");
        let o = run("Rotation: FALSE");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 70.0);
    }
}
