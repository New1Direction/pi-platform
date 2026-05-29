//! Port of `pi_micro_agents/pi_docker_image_scanner.py`.
//!
//! Specialized container image security scanner targeting insecure base
//! images, missing root switches, and exposed credentials. Behaviour is a
//! line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub dockerfile_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub detected_vulnerabilities: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: this is defined in the Python source but is NEVER referenced inside
/// `scan_docker_image`, so it has no effect on the output. Kept here for
/// faithfulness only.
#[allow(dead_code)]
fn is_strict_mode() -> bool {
    match std::env::var("PI_DOCKER_IMAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn scan(input: &Input) -> Output {
    let content = &input.dockerfile_content;
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    let lines = pyutil::splitlines(content);
    let mut has_user_defined = false;

    for (i, raw_line) in lines.iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);

        // Detect raw credentials hardcoded in ENV parameters
        if clean_line.starts_with("ENV ") {
            let lower = clean_line.to_lowercase();
            if ["key", "secret", "password", "token", "auth"]
                .iter()
                .any(|kwd| lower.contains(kwd))
            {
                findings.push(format!(
                    "Line {idx}: Insecure ENV definition containing sensitive credential keywords."
                ));
                risk_score += 30.0;
            }
        }

        // Detect root execution
        if clean_line.starts_with("USER ") {
            // Python: clean_line.split("USER", 1)[1].strip().lower()
            let after = clean_line.splitn(2, "USER").nth(1).unwrap_or("");
            let user_val = pyutil::strip(after).to_lowercase();
            if user_val.contains("root") || user_val == "0" {
                findings.push(format!(
                    "Line {idx}: Explicit execution as root is active."
                ));
                risk_score += 25.0;
            } else {
                has_user_defined = true;
            }
        }

        // Detect insecure base image
        if clean_line.starts_with("FROM ") {
            // Python: clean_line.split("FROM", 1)[1].strip().lower()
            let after = clean_line.splitn(2, "FROM").nth(1).unwrap_or("");
            let image_val = pyutil::strip(after).to_lowercase();
            if image_val.contains("latest") || !image_val.contains(':') {
                findings.push(format!(
                    "Line {idx}: Using unpinned or 'latest' base image tag."
                ));
                risk_score += 20.0;
            }
        }
    }

    // If no USER is defined, warn (defaults to root)
    if !has_user_defined
        && lines
            .iter()
            .any(|l| pyutil::strip(l).starts_with("FROM "))
    {
        findings.push(
            "No explicit USER definition found; container defaults to root execution.".to_string(),
        );
        risk_score += 15.0;
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if is_secure { "PASSED" } else { "FAILED" }.to_string();

    Output {
        is_secure,
        detected_vulnerabilities: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        scan(&Input {
            file_path: "Dockerfile".into(),
            dockerfile_content: content.into(),
        })
    }

    #[test]
    fn clean_pinned_image_with_user_passes() {
        // FROM with pinned tag (no "latest", has ':'), explicit non-root USER.
        let o = run("FROM python:3.11-slim\nUSER appuser\nCMD [\"run\"]");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.detected_vulnerabilities.is_empty());
    }

    #[test]
    fn root_user_and_latest_and_secret_env_flagged() {
        // USER root (+25), FROM ubuntu:latest (+20 latest), ENV with secret (+30)
        // = 75.0, no missing-user warning because has_user_defined stays false
        // but a USER line exists as root... still no_user warning triggers since
        // has_user_defined is false and a FROM exists (+15) => 90.0.
        let o = run("FROM ubuntu:latest\nUSER root\nENV API_KEY=abc123");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.detected_vulnerabilities.len(), 4);
    }

    #[test]
    fn unpinned_image_no_user_flagged() {
        // FROM alpine (no ':' => +20), no USER => +15 = 35.0 < 40 => secure
        let o = run("FROM alpine\nRUN echo hi");
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 35.0);
        assert_eq!(o.detected_vulnerabilities.len(), 2);
    }

    #[test]
    fn empty_content_is_secure() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASSED");
        assert!(o.detected_vulnerabilities.is_empty());
    }
}
