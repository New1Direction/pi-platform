//! Port of `pi_micro_agents/pi_cloud_config_auditor.py`.
//!
//! Deterministic security auditing of AWS, GCP, and Azure resource configs.
//! Behaviour is a line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub config_content: String,
    pub provider: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub misconfigured_resources: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strict iff the value (case-insensitively) equals "true". If the env var is
/// not set, defaults to strict (`true`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_CLOUD_CONFIG_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_config(input: &Input) -> Output {
    let content = &input.config_content;
    let provider = input.provider.to_lowercase();
    let mut misconfigs: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Unrestricted security groups (0.0.0.0/0 ingress)
    if content.contains("0.0.0.0/0") || content.contains("::/0") {
        if content.contains("IpProtocol: -1")
            || content.contains("IpProtocol: tcp")
            || content.contains("port_range")
        {
            misconfigs.push(
                "Unrestricted Firewall Rule: Security group exposes ports to all IPv4/IPv6 addresses."
                    .to_string(),
            );
            risk_score = risk_score.max(80.0);
        }
    }

    // AWS public buckets or public endpoints
    if provider == "aws" {
        if content.contains("BlockPublicAcls: false")
            || content.contains("IgnorePublicAcls: false")
        {
            misconfigs.push(
                "AWS S3 Public Access: S3 Bucket public access block is explicitly disabled."
                    .to_string(),
            );
            risk_score = risk_score.max(85.0);
        }
    }

    // Logging disabled
    if content.contains("logging: disabled")
        || content.contains("enable_flow_logs = false")
        || content.contains("logging: false")
    {
        misconfigs.push(
            "Logging Disabled: Resource logging or VPC Flow Logs are disabled.".to_string(),
        );
        risk_score = risk_score.max(50.0);
    }

    // GCP default network exposure
    if provider == "gcp" && content.contains("default") {
        if content.contains("network: default") || content.contains("subnetwork: default") {
            misconfigs.push(
                "GCP Default Network: GCE instances are placed on the unhardened default VPC network."
                    .to_string(),
            );
            risk_score = risk_score.max(45.0);
        }
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "NON_COMPLIANT".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_NON_COMPLIANCE".to_string();
    }

    Output {
        is_secure: is_sec,
        misconfigured_resources: misconfigs,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_config(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str, provider: &str) -> Output {
        audit_config(&Input {
            file_path: "config.yaml".into(),
            config_content: content.into(),
            provider: provider.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("network: hardened\nlogging: enabled", "aws");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.misconfigured_resources.is_empty());
    }

    #[test]
    fn aws_public_bucket_flagged() {
        let o = run("BlockPublicAcls: false", "AWS");
        assert!(!o.is_secure);
        assert_eq!(o.status, "NON_COMPLIANT");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.misconfigured_resources.len(), 1);
    }

    #[test]
    fn logging_disabled_only_warns_under_threshold() {
        // risk_score 50.0 > 30.0 -> strict mode (default) makes it non-compliant
        let o = run("logging: disabled", "gcp");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.status, "NON_COMPLIANT");
    }

    #[test]
    fn gcp_default_network_flagged() {
        let o = run("network: default", "gcp");
        // risk_score 45.0 > 30.0 -> non-compliant under strict default
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 45.0);
        assert_eq!(o.misconfigured_resources.len(), 1);
    }
}
