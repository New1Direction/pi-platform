//! Port of `pi_micro_agents/pi_sbom_validator.py`.
//!
//! Validates SPDX/CycloneDX SBOMs for license compliance and missing
//! signatures/attestations. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub sbom_path: String,
    pub sbom_content: String,
    pub format: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub license_issues: Vec<String>,
    pub missing_attestations: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true". When the var is unset, defaults to true.
fn is_strict_mode() -> bool {
    match std::env::var("PI_SBOM_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn validate_sbom(input: &Input) -> Output {
    let content = input.sbom_content.to_lowercase();
    let mut license_issues: Vec<String> = Vec::new();
    let mut missing_attestations: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Check for banned licenses (copyleft licenses that violate standard enterprise compliance rules)
    if content.contains("agpl") || content.contains("agpl-3.0") {
        license_issues.push("Banned Copyleft License: AGPL-3.0 detected in dependency tree.".to_string());
        risk_score = risk_score.max(85.0);
    } else if content.contains("gpl-3.0") || content.contains("gplv3") {
        license_issues.push("Risky Copyleft License: GPL-3.0 detected in dependency tree.".to_string());
        risk_score = risk_score.max(50.0);
    }

    // Check for missing signature / attestation patterns
    if !content.contains("signature") && !content.contains("attestation") {
        missing_attestations
            .push("Missing Cryptographic Signature: No attestation blocks found in SBOM.".to_string());
        risk_score = risk_score.max(60.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_SBOM_VALIDATION".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_SBOM_VALIDATION".to_string();
    }

    Output {
        is_secure: is_sec,
        license_issues,
        missing_attestations,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = validate_sbom(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        validate_sbom(&Input {
            sbom_path: "sbom.json".into(),
            sbom_content: content.into(),
            format: "cyclonedx".into(),
        })
    }

    #[test]
    fn clean_sbom_passes() {
        // has a signature, no banned licenses -> no risk, PASSED
        let o = run("{\"components\": [], \"signature\": \"abc\"}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.license_issues.is_empty());
        assert!(o.missing_attestations.is_empty());
    }

    #[test]
    fn agpl_banned_fails_in_strict() {
        // contains AGPL and a signature -> only license issue, risk 85, FAILED in strict
        let o = run("license: AGPL-3.0 with signature present");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.status, "FAILED_SBOM_VALIDATION");
        assert_eq!(
            o.license_issues,
            vec!["Banned Copyleft License: AGPL-3.0 detected in dependency tree."]
        );
        assert!(o.missing_attestations.is_empty());
    }

    #[test]
    fn gpl3_risky_with_missing_attestation() {
        // GPL-3.0 (50) and no signature/attestation (60) -> max 60, FAILED in strict
        let o = run("dependency uses GPL-3.0 license");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.status, "FAILED_SBOM_VALIDATION");
        assert_eq!(
            o.license_issues,
            vec!["Risky Copyleft License: GPL-3.0 detected in dependency tree."]
        );
        assert_eq!(
            o.missing_attestations,
            vec!["Missing Cryptographic Signature: No attestation blocks found in SBOM."]
        );
    }
}
