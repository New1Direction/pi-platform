//! Port of `pi_micro_agents/pi_zero_trust_verifier.py`.
//!
//! Validates service connectivity restrictions, ingress/egress rules, and
//! mutual TLS controls to enforce Zero-Trust. Behaviour is a line-for-line
//! mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub network_policy_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub violations: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: returns `True` unless the env var is set, in
/// which case it returns whether the (lowercased) value equals "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ZERO_TRUST_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn verify_zero_trust(input: &Input) -> Output {
    let content = input.network_policy_content.to_lowercase();
    let mut violations: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Allow all traffic / wildcard network egress
    if content.contains("ingress: []")
        || content.contains("egress: []")
        || content.contains("from: *")
        || content.contains("to: *")
    {
        violations.push(
            "Implicit Trust Boundaries: Broad wildcard access rules enable implicit service traversal."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    // Insecure transit communication protocols
    if content.contains("http://") || content.contains("ftp://") || content.contains("telnet") {
        violations.push(
            "Insecure Protocol Transit: Plaintext service communication discovered inside boundary."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // Missing mutual TLS enforcement
    if content.contains("mtls: false") || content.contains("require_mtls = false") {
        violations.push(
            "Missing Mutual Authentication: mTLS enforcement is explicitly disabled or turned off."
                .to_string(),
        );
        risk_score = risk_score.max(70.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_ZERO_TRUST_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_ZERO_TRUST".to_string();
    }

    Output {
        is_secure: is_sec,
        violations,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = verify_zero_trust(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        verify_zero_trust(&Input {
            network_policy_content: content.into(),
        })
    }

    #[test]
    fn clean_policy_passes() {
        let o = run("ingress:\n  - from: trusted-namespace\nmtls: true");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.violations.is_empty());
    }

    #[test]
    fn wildcard_access_flagged() {
        let o = run("ingress: []");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_ZERO_TRUST_COMPLIANCE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.violations.len(), 1);
    }

    #[test]
    fn insecure_protocol_flagged() {
        // HTTP:// is uppercased in input -> lowercased before matching.
        let o = run("endpoint: HTTP://service.internal");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.status, "FAILED_ZERO_TRUST_COMPLIANCE");
    }

    #[test]
    fn mtls_disabled_alone_is_warn() {
        // risk_score 70.0 > 30.0, so strict mode fails it; but verify mTLS path.
        let o = run("mtls: false");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.violations.len(), 1);
    }
}
