//! Port of `pi_micro_agents/pi_iac_scanner.py`.
//!
//! Static analysis of Terraform, CloudFormation, and Pulumi files for exposed
//! ports, public buckets, and missing encryption. Behaviour is a line-for-line
//! mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub iac_content: String,
    pub iac_type: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub detected_misconfigs: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_IAC_SCANNER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn scan_iac(input: &Input) -> Output {
    let content = &input.iac_content;
    let mut misconfigs: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Public buckets/ACL check
    if content.contains("public-read")
        || content.contains("Principal\": \"*\"")
        || content.contains("Principal\":\"*\"")
        || content.contains("Principal = \"*\"")
    {
        misconfigs.push(
            "Public Access: S3/Blob storage resource configured with public access or wildcard principal."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // Overly broad ingress ports (e.g. port 22 or 3389 open to 0.0.0.0/0)
    if content.contains("0.0.0.0/0") {
        if content.contains("22") || content.contains("3389") || content.contains("cidr_blocks") {
            misconfigs.push(
                "Exposed Ingress: Administrative ports (22/3389) open to wildcard range (0.0.0.0/0)."
                    .to_string(),
            );
            risk_score = risk_score.max(90.0);
        } else {
            misconfigs.push("Broad Network: Generic wildcard network ingress allowed.".to_string());
            risk_score = risk_score.max(40.0);
        }
    }

    // Missing or disabled encryption
    if content.contains("encryption = \"disabled\"")
        || content.contains("sse_algorithm = \"none\"")
        || content.contains("encryption\": \"false\"")
    {
        misconfigs.push(
            "Unencrypted Resource: Data-at-rest encryption is explicitly disabled or not configured."
                .to_string(),
        );
        risk_score = risk_score.max(75.0);
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
        detected_misconfigs: misconfigs,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_iac(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        scan_iac(&Input {
            file_path: "main.tf".into(),
            iac_content: content.into(),
            iac_type: "terraform".into(),
        })
    }

    #[test]
    fn clean_template_passes() {
        let o = run("resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.detected_misconfigs.is_empty());
    }

    #[test]
    fn public_bucket_flagged() {
        let o = run("acl = \"public-read\"");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.detected_misconfigs.len(), 1);
    }

    #[test]
    fn admin_ingress_flagged() {
        let o = run("cidr_blocks = [\"0.0.0.0/0\"]\nfrom_port = 22");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    fn broad_network_only() {
        // 0.0.0.0/0 present but no "22"/"3389"/"cidr_blocks" substrings.
        // risk 40.0 > 30.0, and strict mode defaults to true, so is_secure -> false.
        let o = run("network = \"0.0.0.0/0\"");
        assert_eq!(o.risk_score, 40.0);
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.detected_misconfigs.len(), 1);
    }
}
