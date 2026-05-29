//! Port of `pi_micro_agents/pi_certificate_rotation_watcher.py`.
//!
//! Enforces short certificate expiration windows, valid CA anchors, and
//! automated rotation policies. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub cert_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict by default; if the env var is set, it is
/// strict only when the value (case-insensitively) equals "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_CERT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn watch_certificate(input: &Input) -> Output {
    let content = input.cert_content.to_lowercase();
    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Self-signed certificate check
    if content.contains("self-signed") || content.contains("selfsigned") {
        issues.push(
            "Self-Signed Certificate: Local root authority used. Real CA is required for production."
                .to_string(),
        );
        risk_score = risk_score.max(75.0);
    }

    // Expiry time checks
    if content.contains("expiring: true")
        || content.contains("expires in 5 days")
        || content.contains("expires_soon")
    {
        issues.push(
            "Expiring Certificate: Certificate lifetime is nearing expiration boundary."
                .to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    // Non-standard or weak key sizes
    if content.contains("rsa-1024") || content.contains("key_size: 1024") {
        issues.push(
            "Weak Key Strength: RSA-1024 detected. RSA-2048 or above is standard.".to_string(),
        );
        risk_score = risk_score.max(80.0);
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
    let out = watch_certificate(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        watch_certificate(&Input {
            cert_content: content.into(),
        })
    }

    #[test]
    fn clean_cert_passes() {
        let o = run("Issued by Real CA, RSA-2048, expires in 365 days");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn self_signed_fails_in_strict_mode() {
        let o = run("This is a SELF-SIGNED certificate");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 75.0);
    }

    #[test]
    fn expiring_dominates_risk_score() {
        // self-signed (75) + expiring (90) -> max is 90
        let o = run("self-signed, EXPIRES_SOON, rsa-1024");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.issues.len(), 3);
    }
}
