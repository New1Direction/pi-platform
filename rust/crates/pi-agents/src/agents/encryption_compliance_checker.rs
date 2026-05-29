//! Port of `pi_micro_agents/pi_encryption_compliance_checker.py`.
//!
//! Verifies that data-at-rest and data-in-transit configurations enforce
//! AES-256/GCM or equivalent standards. Behaviour is a line-for-line mirror of
//! the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub resource_type: String,
    pub config_snippet: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub missing_encryption: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, it is strict only when the
/// value (case-insensitively) equals "true"; if unset, defaults to strict.
fn is_strict_mode() -> bool {
    match std::env::var("PI_ENCRYPTION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn check_encryption_compliance(input: &Input) -> Output {
    let snippet = input.config_snippet.to_lowercase();
    let mut gaps: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Reject legacy or insecure crypto algorithms
    if snippet.contains("des") || snippet.contains("rc4") || snippet.contains("md5") {
        gaps.push(
            "Weak Cryptographic Algorithm: Deprecated cryptos (DES, RC4, or MD5) detected."
                .to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    if snippet.contains("ssl")
        || snippet.contains("tlsv1.0")
        || snippet.contains("tlsv1.1")
        || snippet.contains("tls 1.0")
        || snippet.contains("tls 1.1")
    {
        gaps.push(
            "Insecure Protocol Version: Legacy TLS/SSL protocol active. TLS 1.2 or TLS 1.3 is required."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    if snippet.contains("encryption: false")
        || snippet.contains("encrypt=false")
        || snippet.contains("unencrypted")
        || snippet.contains("encryption: disabled")
    {
        gaps.push("Disabled Encryption: Encryption is explicitly turned off.".to_string());
        risk_score = risk_score.max(85.0);
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
        missing_encryption: gaps,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_encryption_compliance(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(resource_type: &str, config_snippet: &str) -> Output {
        check_encryption_compliance(&Input {
            resource_type: resource_type.into(),
            config_snippet: config_snippet.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("database", "encryption: AES-256-GCM enabled");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.missing_encryption.is_empty());
    }

    #[test]
    fn weak_algorithm_fails_in_strict_mode() {
        // No env override -> strict by default.
        let o = run("connection", "cipher = 3DES-CBC");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.missing_encryption.len(), 1);
    }

    #[test]
    fn legacy_tls_only_warn_threshold() {
        // ssl -> risk 80 > 30, strict default -> FAILED.
        let o = run("connection", "protocol = SSLv3");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
    }
}
