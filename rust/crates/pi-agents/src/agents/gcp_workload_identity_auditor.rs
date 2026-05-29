//! Port of `pi_micro_agents/pi_gcp_workload_identity_auditor.py`.
//!
//! Audits deployment configurations to verify GCP Workload Identity compliance
//! standards and flags insecure static service account keys. Behaviour is a
//! line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub uses_service_account_key_file: bool,
    pub has_workload_identity_binding: bool,
    pub service_account_email: String,
    #[serde(default = "default_deployment_target")]
    pub deployment_target: String,
}

fn default_deployment_target() -> String {
    "gke".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_compliant: bool,
    pub risk_score: f64,
    pub recommendation: String,
    pub issues: Vec<String>,
    pub status: String,
}

pub fn execute(input: &Input) -> Output {
    let uses_key_file = input.uses_service_account_key_file;
    let has_binding = input.has_workload_identity_binding;
    let sa_email = &input.service_account_email;
    let target = &input.deployment_target;

    let mut issues: Vec<String> = Vec::new();
    let mut recommendations: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // 1. Physical key file check
    if uses_key_file {
        issues.push(
            "VULNERABILITY: Workload is using a static service account private key file. \
Static key files present high credential exposure risks."
                .to_string(),
        );
        risk_score += 40.0;
        recommendations.push(
            "Disable static service account key files. Transition to IAM Workload Identity \
or dynamic instance metadata credentials."
                .to_string(),
        );
    }

    // 2. Workload Identity binding check
    if target.to_lowercase() == "gke" && !has_binding {
        issues.push(
            "WARNING: Workload on GKE is active without a Workload Identity binding. \
It may fall back to GCE node default service account credentials."
                .to_string(),
        );
        risk_score += 30.0;
        recommendations.push(
            "Enable Workload Identity on GKE. Bind the Kubernetes Service Account (KSA) \
to a dedicated GCP Service Account (GSA) using IAM binding rules."
                .to_string(),
        );
    }

    // 3. Default service account checks
    let mut is_default_sa = false;
    if !sa_email.is_empty() {
        let sa_email_lower = sa_email.to_lowercase();
        if sa_email_lower.ends_with("-compute@developer.gserviceaccount.com")
            || sa_email_lower.ends_with("@appspot.gserviceaccount.com")
            || sa_email_lower.starts_with("default-")
        {
            is_default_sa = true;
        }
    }

    if is_default_sa {
        issues.push(format!(
            "WARNING: Workload is configured to use a GCP default service account ('{sa_email}'). \
Default service accounts contain excessive permissions."
        ));
        risk_score += 25.0;
        recommendations.push(
            "Create a dedicated, fine-grained service account following the Principle of Least Privilege, \
and bind it to the workload instead of the default."
                .to_string(),
        );
    }

    // 4. Check email format
    if !sa_email.is_empty() {
        if !sa_email.contains('@') || !sa_email.contains('.') {
            issues.push(format!(
                "Invalid service account email format: '{sa_email}'."
            ));
            risk_score += 15.0;
        }
    }

    risk_score = risk_score.min(100.0);
    let is_compliant = risk_score < 50.0;

    let status = if risk_score >= 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 30.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    let recommendation_str = if !recommendations.is_empty() {
        recommendations.join(" ")
    } else {
        "Security posture is excellent. No changes required.".to_string()
    };

    Output {
        is_compliant,
        risk_score,
        recommendation: recommendation_str,
        issues,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = execute(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(
        uses_key_file: bool,
        has_binding: bool,
        sa_email: &str,
        target: &str,
    ) -> Output {
        execute(&Input {
            uses_service_account_key_file: uses_key_file,
            has_workload_identity_binding: has_binding,
            service_account_email: sa_email.into(),
            deployment_target: target.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        // No key file, gke with binding, dedicated valid SA -> 0 risk
        let o = run(false, true, "app-runtime@my-project.iam.gserviceaccount.com", "gke");
        assert!(o.is_compliant);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASS");
        assert!(o.issues.is_empty());
        assert_eq!(o.recommendation, "Security posture is excellent. No changes required.");
    }

    #[test]
    fn key_file_only_warn() {
        // key file -> 40.0 -> WARN, not compliant
        let o = run(true, true, "app@my-project.iam.gserviceaccount.com", "cloud_run");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(o.status, "WARN");
        // 40.0 < 50.0 so is_compliant stays true (mirrors Python)
        assert!(o.is_compliant);
        assert_eq!(o.issues.len(), 1);
    }

    #[test]
    fn key_file_and_gke_no_binding_fails() {
        // 40 + 30 = 70 -> FAIL
        let o = run(true, false, "app@my-project.iam.gserviceaccount.com", "gke");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.status, "FAIL");
        assert!(!o.is_compliant);
        assert_eq!(o.issues.len(), 2);
    }

    #[test]
    fn default_sa_and_bad_email_capped() {
        // key(40) + gke no binding(30) + default sa(25) + bad email(15) = 110 -> capped 100
        let o = run(true, false, "default-sa", "GKE");
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.status, "FAIL");
        assert!(!o.is_compliant);
        assert_eq!(o.issues.len(), 4);
    }

    #[test]
    fn empty_email_skips_email_checks() {
        // empty email -> no default sa check, no email format check
        let o = run(false, true, "", "cloud_run");
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASS");
        assert!(o.issues.is_empty());
    }
}
