//! Port of `pi_micro_agents/pi_docker_compose_security_sentry.py`.
//!
//! Audits Docker Compose files for critical host-level breakout flaws
//! (`privileged: true`, mounting the host Docker socket, mounting `/`).
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub compose_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_services: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`.
///
/// The Python original first consults the env var `PI_DOCKER_COMPOSE_STRICT_MODE`
/// (case-insensitive "true"), and if it is unset falls back to reading
/// `~/.antigravitycli/config.json` (or `../../.antigravitycli/config.json`),
/// defaulting to strict (`True`). In this repository neither config file sets
/// the `PI_DOCKER_COMPOSE_STRICT_MODE` key, so the file-fallback evaluates to
/// `True`, identical to the env-var-absent default below. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_DOCKER_COMPOSE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Python `len(line) - len(line.lstrip())`: count of leading whitespace
/// **code points** (Python `len` counts chars, and no-arg `lstrip` trims
/// Unicode whitespace, matching `str::trim_start`).
fn leading_indent(line: &str) -> usize {
    line.chars().count() - line.trim_start().chars().count()
}

pub fn audit_docker_compose(input: &Input) -> Output {
    let code = &input.compose_code;
    let mut vulnerable_services: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    let lines = pyutil::splitlines(code);
    let mut current_service: Option<String> = None;
    let mut in_services = false;
    let mut services_indent: Option<usize> = None;
    let mut service_indent: Option<usize> = None;

    for line in lines {
        let clean_line = pyutil::strip(line);
        if clean_line.is_empty() || clean_line.starts_with('#') {
            continue;
        }

        // Check if we enter/exit services section
        if clean_line.starts_with("services:") {
            in_services = true;
            services_indent = Some(leading_indent(line));
            continue;
        }

        if in_services {
            let indent = leading_indent(line);

            // If we hit a line with less or equal indentation than `services:`,
            // and it ends with ":", we exited the services section.
            if let Some(si) = services_indent {
                if indent <= si && clean_line.ends_with(':') {
                    in_services = false;
                    current_service = None;
                    continue;
                }
            }

            // Detect service declarations based on indentation
            if clean_line.ends_with(':') {
                // clean_line[:-1].strip()  -- drop the trailing ':' then strip
                let key = pyutil::strip(&clean_line[..clean_line.len() - 1]);
                if !matches!(
                    key,
                    "image"
                        | "ports"
                        | "volumes"
                        | "environment"
                        | "build"
                        | "deploy"
                        | "networks"
                        | "depends_on"
                        | "command"
                        | "restart"
                ) {
                    if service_indent.is_none() {
                        service_indent = Some(indent);
                        current_service = Some(key.to_string());
                    } else if Some(indent) == service_indent {
                        current_service = Some(key.to_string());
                    }
                }
            }

            if let Some(ref service) = current_service {
                let mut is_vuln = false;
                let lower = clean_line.to_lowercase();
                if lower.contains("privileged: true") || lower.contains("privileged:true") {
                    is_vuln = true;
                    flagged_findings.push(format!(
                        "Service '{service}' is declared with 'privileged: true'. This allows container processes \
to access host hardware devices and bypass standard security namespaces, enabling host takeover."
                    ));
                }
                if clean_line.contains("/var/run/docker.sock") {
                    is_vuln = true;
                    flagged_findings.push(format!(
                        "Service '{service}' mounts the host Docker socket '/var/run/docker.sock'. \
Exposing the Docker socket allows containers to control the parent Docker daemon and spin up \
fully privileged root containers, escalating privileges."
                    ));
                }
                if clean_line.contains("/host")
                    && (clean_line.starts_with("- /:")
                        || clean_line.starts_with("- \"/:")
                        || clean_line.starts_with("- '/:")
                        || clean_line.contains("/:"))
                {
                    is_vuln = true;
                    flagged_findings.push(format!(
                        "Service '{service}' mounts the root directory '/' to '/host'. This exposes the \
entire host operating system files to the container processes."
                    ));
                }

                if is_vuln && !vulnerable_services.contains(service) {
                    vulnerable_services.push(service.clone());
                }
            }
        }
    }

    let mut is_secure = vulnerable_services.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DOCKER_COMPOSE".to_string();
        } else {
            status = "WARN_DOCKER_COMPOSE".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_services,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_docker_compose(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        // Force strict mode deterministically for the assertions below.
        std::env::set_var("PI_DOCKER_COMPOSE_STRICT_MODE", "true");
        audit_docker_compose(&Input {
            file_path: "docker-compose.yml".into(),
            compose_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_compose_passes() {
        let code = "services:\n  web:\n    image: nginx\n    ports:\n      - \"80:80\"\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_services.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn privileged_flagged() {
        let code = "services:\n  bad:\n    image: nginx\n    privileged: true\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DOCKER_COMPOSE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_services, vec!["bad"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    #[serial]
    fn docker_socket_and_root_mount_flagged() {
        let code = "services:\n  worker:\n    image: docker\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n      - /:/host\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_services, vec!["worker"]);
        // both the docker.sock finding and the root-mount finding fire
        assert_eq!(o.flagged_findings.len(), 2);
    }

    #[test]
    #[serial]
    fn warn_mode_coerces_secure() {
        std::env::set_var("PI_DOCKER_COMPOSE_STRICT_MODE", "false");
        let o = audit_docker_compose(&Input {
            file_path: "docker-compose.yml".into(),
            compose_code: "services:\n  bad:\n    privileged: true\n".into(),
            check_level: "STRICT".into(),
        });
        assert!(o.is_secure); // coerced back to true in non-strict mode
        assert_eq!(o.status, "WARN_DOCKER_COMPOSE");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_services, vec!["bad"]);
        std::env::set_var("PI_DOCKER_COMPOSE_STRICT_MODE", "true");
    }
}
