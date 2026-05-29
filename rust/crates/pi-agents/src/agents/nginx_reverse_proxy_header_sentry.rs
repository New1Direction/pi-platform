//! Port of `pi_micro_agents/pi_nginx_reverse_proxy_header_sentry.py`.
//!
//! Audits Nginx reverse-proxy `location` blocks: any block that runs
//! `proxy_pass` but does not configure `X-Forwarded-For` / `proxy_set_header`
//! tracking headers is flagged. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub nginx_code: String,
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

/// Mirrors `is_strict_mode()`: strict by default; if the env var is set, it is
/// strict only when its value is (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_NGINX_REVERSE_PROXY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python: re.findall(r'location\s+([a-zA-Z0-9_\-\./]+)\s*\{([\s\S]*?)\}', code)
// Two capture groups, no lookaround/backreferences -> directly portable.
static LOCATION_BLOCK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"location\s+([a-zA-Z0-9_\-\./]+)\s*\{([\s\S]*?)\}").unwrap());

pub fn audit_nginx_headers(input: &Input) -> Output {
    let code = &input.nginx_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find location blocks. re.findall with 2 groups -> iterate captures,
    // pulling group 1 (path) and group 2 (body).
    for caps in LOCATION_BLOCK_RE.captures_iter(code) {
        let path = caps.get(1).map_or("", |m| m.as_str());
        let body = caps.get(2).map_or("", |m| m.as_str());

        if body.contains("proxy_pass") {
            // If there's proxy_pass, check if standard headers are set to
            // prevent spoofing, e.g. X-Forwarded-For or X-Real-IP.
            let has_forwarded_for =
                body.contains("X-Forwarded-For") || body.contains("proxy_set_header");
            if !has_forwarded_for {
                vulnerable_elements.push(path.to_string());
                flagged_findings.push(format!(
                    "Location block '{path}' executes proxy_pass but fails to configure 'X-Forwarded-For' or standard tracking headers. \
This can mask client source IPs and lead to access control bypasses or spoofing vulnerabilities."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_NGINX_REVERSE_PROXY".to_string();
        } else {
            status = "WARN_NGINX_REVERSE_PROXY".to_string();
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
    let out = audit_nginx_headers(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_nginx_headers(&Input {
            file_path: "nginx.conf".into(),
            nginx_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_with_proxy_set_header_passes() {
        let o = run("location /api { proxy_pass http://backend; proxy_set_header Host $host; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn proxy_pass_without_headers_flagged() {
        let o = run("location /app { proxy_pass http://up; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_NGINX_REVERSE_PROXY");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_elements, vec!["/app"]);
    }

    #[test]
    fn no_proxy_pass_is_secure() {
        let o = run("location /static { root /var/www; }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
