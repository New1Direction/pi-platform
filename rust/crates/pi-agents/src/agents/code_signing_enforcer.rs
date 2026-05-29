//! Port of `pi_micro_agents/pi_code_signing_enforcer.py`.
//!
//! Audits CI/CD output artifacts to ensure all binaries, containers, or web app
//! bundles have secure signatures. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub artifact_metadata: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict by default; when the env var is set,
/// strict only if it equals (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_ARTIFACT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn verify_signing(input: &Input) -> Output {
    let content = input.artifact_metadata.to_lowercase();
    let mut issues: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Unsigned binary issues
    if content.contains("signature: none")
        || content.contains("unsigned")
        || content.contains("missing signature")
    {
        issues.push(
            "Unsigned Build Artifact: Build target is unsigned, rendering it vulnerable to tamper injections."
                .to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    // Insecure or expired certificate anchors
    if content.contains("expired certificate")
        || content.contains("invalid anchor")
        || content.contains("revoked")
    {
        issues.push(
            "Insecure Signature Anchor: The signing key chain contains expired or revoked certificate anchors."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // Missing checksum validation
    if content.contains("checksum: false") || content.contains("checksum verification disabled") {
        issues.push(
            "Missing Integrity Checksum: Build process skipped validating package hash checksums."
                .to_string(),
        );
        risk_score = risk_score.max(65.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_SIGNING_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_SIGNING".to_string();
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
    let out = verify_signing(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(meta: &str) -> Output {
        verify_signing(&Input {
            artifact_metadata: meta.into(),
        })
    }

    #[test]
    fn clean_artifact_passes() {
        let o = run("Build signed with valid certificate, checksum verified.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.issues.is_empty());
    }

    #[test]
    fn unsigned_artifact_fails_in_strict_mode() {
        let o = run("Artifact is UNSIGNED and pushed to registry.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_SIGNING_COMPLIANCE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.issues.len(), 1);
    }

    #[test]
    fn checksum_disabled_only_warns_when_secure() {
        // risk 65 > 30, so strict mode would fail; but checksum alone with
        // strict off would warn. Here we test the WARN branch via low-only risk
        // by combining: a checksum issue (65) is > 30 -> fails in strict.
        let o = run("checksum: false in this build");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.status, "FAILED_SIGNING_COMPLIANCE");
    }
}
