//! Port of `pi_micro_agents/pi_api_reverse_engineered_auth.py`.
//!
//! Audits application integrations for weakly signed custom JWTs or hardcoded
//! authentication payloads. Behaviour is a line-for-line mirror of the Python
//! original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub auth_code: String,
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

// Mirrors the Python regex:
//   r'(jwt\.sign\([\s\S]*?,\s*["\'][a-zA-Z0-9_\-]+["\']|algorithm\s*:\s*["\']none["\']|["\']?Authorization["\']?\s*:\s*["\']Bearer\s+ey[a-zA-Z0-9_\-\.]*["\'])'
// A single capturing group with three alternatives. `[\s\S]` matches any char
// including newlines (this is why DOTALL is not needed). No lookaround or
// backreferences are used, so the Rust `regex` crate handles it directly.
static WEAK_AUTH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(jwt\.sign\([\s\S]*?,\s*["'][a-zA-Z0-9_\-]+["']|algorithm\s*:\s*["']none["']|["']?Authorization["']?\s*:\s*["']Bearer\s+ey[a-zA-Z0-9_\-\.]*["'])"#,
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_API_REVERSE_ENGINEER_AUTH_STRICT_MODE`:
/// if set, returns `value.lower() == "true"`. If unset, it falls back to a
/// `~/.antigravitycli/config.json` config file (defaulting to `True` if the
/// file is absent / unreadable / missing the key). We mirror the env-var branch
/// exactly and default to `true` when the env var is unset, matching the Python
/// default when no config file overrides it. See module `deviations` notes.
fn is_strict_mode() -> bool {
    match std::env::var("PI_API_REVERSE_ENGINEER_AUTH_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_reverse_auth(input: &Input) -> Output {
    let code = &input.auth_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find weakly signed custom JWT signatures or insecure hardcoded
    // authentication headers (re.search -> leftmost match, group(1)).
    if let Some(caps) = WEAK_AUTH_PATTERN.captures(code) {
        let g1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        vulnerable_elements.push(g1.to_string());
        flagged_findings.push(format!(
            "Authentication setup contains weak key signature or hardcoded token parameter: '{g1}'. \
Using hardcoded authorization keys or insecure token signing methods enables reverse-engineering and session spoofing."
        ));
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_REVERSE_AUTH".to_string();
        } else {
            status = "WARN_REVERSE_AUTH".to_string();
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
    let out = audit_reverse_auth(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_reverse_auth(&Input {
            file_path: "client.js".into(),
            auth_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("const t = jwt.sign(payload, privateKeyVariable)");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn hardcoded_jwt_secret_flagged() {
        let o = run("const t = jwt.sign(payload, \"mysecret\")");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_REVERSE_AUTH");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["jwt.sign(payload, \"mysecret\""]);
    }

    #[test]
    fn algorithm_none_flagged() {
        let o = run("options = { algorithm: 'none' }");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["algorithm: 'none'"]);
    }

    #[test]
    fn hardcoded_bearer_token_flagged() {
        let o = run("headers = { \"Authorization\": \"Bearer eyJhbGciOi\" }");
        assert!(!o.is_secure);
        assert_eq!(
            o.vulnerable_elements,
            vec!["\"Authorization\": \"Bearer eyJhbGciOi\""]
        );
    }
}
