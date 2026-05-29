//! Port of `pi_micro_agents/pi_docker_socket_privilege_sentry.py`.
//!
//! Audits Dockerfile / run configurations for mounts of the Docker socket
//! (`/var/run/docker.sock`), which permits container-to-host privilege
//! escalation. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub dockerfile_code: String,
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
    match std::env::var("PI_DOCKER_SOCKET_PRIVILEGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_docker_socket(input: &Input) -> Output {
    let code = &input.dockerfile_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Detection uses the RAW line; the finding message uses line.strip().
    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        if raw_line.contains("docker.sock") {
            let stripped = pyutil::strip(raw_line);
            vulnerable_elements.push(format!("Line {idx}"));
            flagged_findings.push(format!(
                "Line {idx}: Reference to Docker socket mount detected: '{stripped}'. \
Mounting the Docker socket inside a container allows escalation of privilege to full host takeover."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DOCKER_SOCKET_PRIVILEGE".to_string();
        } else {
            status = "WARN_DOCKER_SOCKET_PRIVILEGE".to_string();
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
    let out = audit_docker_socket(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_docker_socket(&Input {
            file_path: "Dockerfile".into(),
            dockerfile_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("FROM alpine\nRUN echo hello");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn socket_mount_flagged() {
        let o = run("    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DOCKER_SOCKET_PRIVILEGE");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 2"]);
        assert!(o.flagged_findings[0].contains(
            "'- /var/run/docker.sock:/var/run/docker.sock'"
        ));
    }

    #[test]
    fn empty_input_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_elements.is_empty());
        assert!(o.flagged_findings.is_empty());
    }
}
