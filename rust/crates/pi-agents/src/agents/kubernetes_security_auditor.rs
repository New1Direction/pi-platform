//! Port of `pi_micro_agents/pi_kubernetes_security_auditor.py`.
//!
//! Audits Kubernetes manifests for privileged execution, default namespace,
//! missing resource constraints, and hostPath mounts. Behaviour is a
//! line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub k8s_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub violations: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, returns whether it equals
/// (case-insensitively) "true"; otherwise defaults to strict (true).
fn is_strict_mode() -> bool {
    match std::env::var("PI_K8S_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_k8s(input: &Input) -> Output {
    let content = &input.k8s_content;
    let mut violations: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Privileged Container running
    if content.contains("privileged: true") || content.contains("\"privileged\": true") {
        violations.push(
            "Privileged Execution: Container configured to run with elevated root privileges."
                .to_string(),
        );
        risk_score = risk_score.max(95.0);
    }

    // Namespace defaults
    if content.contains("namespace: default") || content.contains("\"namespace\": \"default\"") {
        violations.push(
            "Default Namespace: Resources are explicitly scheduled in the unhardened default namespace."
                .to_string(),
        );
        risk_score = risk_score.max(40.0);
    }

    // Resource limits missing
    if !content.contains("resources:") && !content.contains("\"resources\"") {
        violations.push(
            "Missing Resource Constraints: CPU and Memory limit fields are missing from container spec."
                .to_string(),
        );
        risk_score = risk_score.max(60.0);
    }

    // HostPath / Node volume sharing
    if content.contains("hostPath:") || content.contains("\"hostPath\"") {
        violations.push(
            "Host Path Injection: Direct volume mapping to node local directory detected."
                .to_string(),
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
        violations,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_k8s(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        audit_k8s(&Input {
            k8s_content: content.into(),
        })
    }

    #[test]
    fn clean_manifest_with_resources_passes() {
        // Has resources:, no privileged/default-ns/hostPath -> no violations.
        let o = run(
            "spec:\n  containers:\n  - name: app\n    resources:\n      limits:\n        cpu: 100m",
        );
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASSED");
        assert!(o.violations.is_empty());
    }

    #[test]
    fn privileged_container_flagged() {
        let o = run("securityContext:\n  privileged: true\nresources:\n  limits: {}");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.violations.len(), 1);
    }

    #[test]
    fn missing_resources_only_warns_below_strict_threshold() {
        // No "resources:" -> 60.0 risk, which is > 30 so under strict -> FAILED.
        let o = run("spec:\n  containers:\n  - name: app");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
    }

    #[test]
    fn default_namespace_with_resources_present() {
        // namespace: default -> 40.0, plus resources present so no missing-resource hit.
        let o = run("metadata:\n  namespace: default\nspec:\n  resources: {}");
        assert_eq!(o.risk_score, 40.0);
        // 40 > 30, strict default -> FAILED
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_COMPLIANCE");
        assert_eq!(o.violations.len(), 1);
    }
}
