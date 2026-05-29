//! Port of `pi_micro_agents/pi_kubernetes_root_execution_linter.py`.
//!
//! Audits Kubernetes manifests to enforce `runAsNonRoot: true` and flag
//! explicit root execution (`runAsUser: 0`) or missing securityContext.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub yaml_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_KUBERNETES_ROOT_EXECUTION_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_kubernetes_root(input: &Input) -> Output {
    let code = &input.yaml_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Parse YAML manifests for runAsNonRoot and runAsUser
    // Simple line-by-line / section-based checks to ensure safety
    let lines = pyutil::splitlines(code);
    let mut has_security_context = false;
    let mut has_run_as_non_root = false;

    for (i, line) in lines.into_iter().enumerate() {
        let idx = i + 1;
        if line.contains("securityContext:") {
            has_security_context = true;
        }
        if line.contains("runAsNonRoot: true") {
            has_run_as_non_root = true;
        }
        if line.contains("runAsUser: 0") || line.contains("runAsUser:0") {
            vulnerable_elements.push(format!("Line {idx}"));
            flagged_findings.push(format!(
                "Line {idx}: Explicit runAsUser is set to root (0). This overrides pod execution boundaries and exposes the host."
            ));
        }
    }

    if has_security_context && !has_run_as_non_root {
        vulnerable_elements.push("securityContext".to_string());
        flagged_findings.push(
            "Manifest specifies securityContext but omits 'runAsNonRoot: true'. This allows containers to execute as root.".to_string(),
        );
    } else if !has_security_context {
        vulnerable_elements.push("missing securityContext".to_string());
        flagged_findings.push(
            "Manifest completely omits securityContext specifications. All container pods should enforce non-root privileges.".to_string(),
        );
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_KUBERNETES_ROOT_EXECUTION".to_string();
        } else {
            status = "WARN_KUBERNETES_ROOT_EXECUTION".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_kubernetes_root(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_kubernetes_root(&Input {
            file_path: "deploy.yaml".into(),
            yaml_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_manifest_passes() {
        // Has securityContext AND runAsNonRoot: true, no runAsUser: 0.
        let o = run("spec:\n  securityContext:\n    runAsNonRoot: true");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn run_as_user_zero_flagged() {
        let o = run("spec:\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 0");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_KUBERNETES_ROOT_EXECUTION");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 4"]);
    }

    #[test]
    fn missing_security_context_flagged() {
        let o = run("spec:\n  containers:\n  - name: app");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_KUBERNETES_ROOT_EXECUTION");
        assert_eq!(o.vulnerable_elements, vec!["missing securityContext"]);
    }

    #[test]
    fn security_context_without_non_root_flagged() {
        let o = run("spec:\n  securityContext:\n    fsGroup: 2000");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["securityContext"]);
    }
}
