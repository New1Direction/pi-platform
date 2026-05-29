//! Port of `pi_micro_agents/pi_docker_compose_port_exposure_sentry.py`.
//!
//! Audits Docker Compose files for wildcard/public bindings that expose
//! administrative or database ports. Behaviour is a line-for-line mirror of the
//! Python original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_DOCKER_COMPOSE_PORT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Python: `len(line) - len(line.lstrip())` — the count of leading whitespace
/// characters. `str.lstrip()` (no-arg) trims Unicode whitespace; Rust's
/// `trim_start` uses the same `White_Space` property. Note Python's length is
/// in code points, not bytes, so we count chars.
fn leading_ws(line: &str) -> usize {
    line.chars().count() - line.trim_start().chars().count()
}

pub fn audit_docker_compose_ports(input: &Input) -> Output {
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

        if clean_line.starts_with("services:") {
            in_services = true;
            services_indent = Some(leading_ws(line));
            continue;
        }

        if in_services {
            let indent = leading_ws(line);

            if let Some(si) = services_indent {
                if indent <= si && clean_line.ends_with(':') {
                    in_services = false;
                    current_service = None;
                    continue;
                }
            }

            if clean_line.ends_with(':') {
                // key = clean_line[:-1].strip()  -- strip last char then trim.
                let key = pyutil::strip(&clean_line[..clean_line.len() - 1]).to_string();
                if !matches!(
                    key.as_str(),
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
                        current_service = Some(key);
                    } else if Some(indent) == service_indent {
                        current_service = Some(key);
                    }
                }
            }

            if let Some(svc) = &current_service {
                // Look for port mapping lines like "- 0.0.0.0:80:80" or
                // "- 3306:3306" or "- 5432:5432".
                if clean_line.starts_with('-') && clean_line.contains(':') {
                    let sensitive_ports = [
                        "3306", "5432", "27017", "6379", "8080", "9200", "22", "23", "9000",
                    ];
                    let exposed_wildcard = clean_line.contains("0.0.0.0")
                        || !["127.0.0.1", "localhost"]
                            .iter()
                            .any(|ip| clean_line.contains(ip));

                    let has_sensitive_port =
                        sensitive_ports.iter().any(|port| clean_line.contains(port));

                    if exposed_wildcard && has_sensitive_port {
                        vulnerable_services.push(svc.clone());
                        flagged_findings.push(format!(
                            "Service '{svc}' exposes sensitive port mapping '{clean_line}' to public 0.0.0.0 interface. \
This permits unauthorized external connectivity to administrative or database backends."
                        ));
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_services.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DOCKER_COMPOSE_PORT".to_string();
        } else {
            status = "WARN_DOCKER_COMPOSE_PORT".to_string();
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
    let out = audit_docker_compose_ports(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_docker_compose_ports(&Input {
            file_path: "docker-compose.yml".into(),
            compose_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_compose_passes() {
        std::env::remove_var("PI_DOCKER_COMPOSE_PORT_STRICT_MODE");
        let code = "services:\n  web:\n    image: nginx\n    ports:\n      - 127.0.0.1:8080:8080\n";
        let o = run(code);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_services.is_empty());
    }

    #[test]
    #[serial]
    fn wildcard_db_port_flagged() {
        std::env::remove_var("PI_DOCKER_COMPOSE_PORT_STRICT_MODE");
        let code = "services:\n  db:\n    image: postgres\n    ports:\n      - 0.0.0.0:5432:5432\n";
        let o = run(code);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DOCKER_COMPOSE_PORT");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_services, vec!["db"]);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns_and_coerces_secure() {
        std::env::set_var("PI_DOCKER_COMPOSE_PORT_STRICT_MODE", "false");
        let code = "services:\n  cache:\n    image: redis\n    ports:\n      - 6379:6379\n";
        let o = run(code);
        // exposed (no localhost) + sensitive port -> vulnerable, but non-strict
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_DOCKER_COMPOSE_PORT");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_services, vec!["cache"]);
        std::env::remove_var("PI_DOCKER_COMPOSE_PORT_STRICT_MODE");
    }
}
