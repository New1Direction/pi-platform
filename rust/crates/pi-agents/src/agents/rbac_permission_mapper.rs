//! Port of `pi_micro_agents/pi_rbac_permission_mapper.py`.
//!
//! Maps IAM/RBAC policies to detect least-privilege violations, wildcard
//! actions/resources, and privilege-escalation risks. Behaviour is a
//! line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub policy_file_path: String,
    pub policy_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub excessive_permissions: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strictness is determined by a case-insensitive comparison to "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_RBAC_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn map_rbac_permissions(input: &Input) -> Output {
    let content = &input.policy_content;
    let mut excessive: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Action: * checks
    if content.contains("\"Action\": \"*\"")
        || content.contains("\"action\": \"*\"")
        || content.contains("Action: '*'")
        || content.contains("action: '*'")
    {
        excessive.push(
            "Wildcard Action: Policy allows arbitrary actions ('*') which violates least-privilege principles.".to_string(),
        );
        risk_score = risk_score.max(95.0);
    }

    // Resource: * checks
    if content.contains("\"Resource\": \"*\"")
        || content.contains("\"resource\": \"*\"")
        || content.contains("Resource: '*'")
        || content.contains("resource: '*'")
    {
        if content.contains("Effect: Allow")
            || content.contains("\"Effect\": \"Allow\"")
            || content.contains("\"effect\": \"allow\"")
        {
            excessive.push(
                "Wildcard Resource: Policy allows actions on all target resources which may cause data leakage.".to_string(),
            );
            risk_score = risk_score.max(70.0);
        }
    }

    // Privilege escalation checks: iam:PassRole or AttachRolePolicy
    if content.contains("iam:PassRole")
        || content.contains("iam:AttachRolePolicy")
        || content.contains("iam:PutUserPolicy")
    {
        excessive.push(
            "Privilege Escalation Risk: Permission grants critical IAM management controls (e.g. iam:PassRole).".to_string(),
        );
        risk_score = risk_score.max(90.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec { "PASSED" } else { "OVERLY_PERMISSIVE" }.to_string();
    if risk_score > 0.0 && is_sec {
        status = "WARN_PERMISSIVE".to_string();
    }

    Output {
        is_secure: is_sec,
        excessive_permissions: excessive,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = map_rbac_permissions(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        map_rbac_permissions(&Input {
            policy_file_path: "policy.json".into(),
            policy_content: content.into(),
        })
    }

    #[test]
    fn clean_policy_passes() {
        let o = run("{\"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::bucket\"}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.excessive_permissions.is_empty());
    }

    #[test]
    fn wildcard_action_flagged() {
        let o = run("{\"Action\": \"*\"}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "OVERLY_PERMISSIVE");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.excessive_permissions.len(), 1);
    }

    #[test]
    fn wildcard_resource_needs_allow_effect() {
        // Resource:* without an Allow effect must NOT be flagged.
        let o = run("{\"Resource\": \"*\"}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);

        // With an Allow effect it is flagged at 70.0.
        let o2 = run("{\"Effect\": \"Allow\", \"Resource\": \"*\"}");
        assert!(!o2.is_secure);
        assert_eq!(o2.risk_score, 70.0);
        assert_eq!(o2.status, "OVERLY_PERMISSIVE");
    }

    #[test]
    fn privilege_escalation_flagged() {
        let o = run("{\"Action\": \"iam:PassRole\"}");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 90.0);
    }
}
