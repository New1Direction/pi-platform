//! Port of `pi_micro_agents/pi_container_escape_detector.py`.
//!
//! Specialized Container Escape and Privilege Escalation vulnerability detector.
//! Behaviour is a line-for-line mirror of the Python original: substring checks
//! over the lowercased configuration content with additive risk scoring.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub config_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub escape_vectors: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

pub fn scan_container_escape(input: &Input) -> Output {
    let content = &input.config_content;
    let lower = content.to_lowercase();
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Look for privileged mode
    if lower.contains("privileged: true") {
        findings.push("Privileged execution flag enabled; provides complete root capabilities.".to_string());
        risk_score += 40.0;
    }

    // Look for host IPC / Network / PID sharing
    if lower.contains("hostnetwork: true")
        || lower.contains("hostpid: true")
        || lower.contains("hostipc: true")
    {
        findings.push(
            "Sharing host namespace (Network, PID, or IPC) can lead to direct node escape."
                .to_string(),
        );
        risk_score += 35.0;
    }

    // Look for writeable hostPath mounts
    if lower.contains("hostpath:") {
        findings.push(
            "Host path volume mount detected; potential for host filesystem tampering."
                .to_string(),
        );
        risk_score += 25.0;
    }

    // Look for dangerous capability additions (e.g. SYS_ADMIN, NET_ADMIN)
    if lower.contains("sys_admin") || lower.contains("net_admin") || lower.contains("all") {
        findings.push("Dangerous Linux capabilities added (e.g. SYS_ADMIN or ALL).".to_string());
        risk_score += 20.0;
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if is_secure { "PASSED" } else { "FAILED" }.to_string();

    Output {
        is_secure,
        escape_vectors: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_container_escape(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        scan_container_escape(&Input {
            file_path: "pod.yaml".into(),
            config_content: content.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.escape_vectors.is_empty());
    }

    #[test]
    fn privileged_flagged() {
        let o = run("securityContext:\n  privileged: true");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(o.escape_vectors.len(), 1);
    }

    #[test]
    fn multiple_vectors_capped() {
        // privileged(40) + hostNetwork(35) + hostPath(25) + sys_admin(20) = 120 -> 100
        let o = run(
            "privileged: true\nhostNetwork: true\nhostPath:\n  path: /\ncapabilities:\n  add: [SYS_ADMIN]",
        );
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.escape_vectors.len(), 4);
    }

    #[test]
    fn all_capability_substring() {
        // "all" is a bare substring match; appears inside "smallpod" too.
        // Score 20.0 < 40.0 so it is still classified PASSED, matching Python.
        let o = run("name: smallpod");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 20.0);
        assert_eq!(o.escape_vectors.len(), 1);
    }
}
