//! Port of `pi_micro_agents/pi_grpc_protocol_interceptor.py`.
//!
//! Specialized gRPC micro-agent that audits service definitions and
//! configuration files for unencrypted payloads or insecure transport options.
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub grpc_code: String,
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

/// Mirrors the single-group alternation regex used by `audit_grpc_interceptor`.
static INSECURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(insecure_channel|insecure_credentials|insecure_server_credentials|insecure_port|InsecureChannel|insecure_connector)",
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`:
///   1. If env var `PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE` is set ->
///      `env_val.lower() == "true"`.
///   2. Else read `~/.antigravitycli/config.json`, falling back to a repo-root
///      `.antigravitycli/config.json`, and return
///      `bool(data.get("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE", True))`.
///   3. Else / on any error -> `True`.
fn is_strict_mode() -> bool {
    if let Ok(env_val) = std::env::var("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE") {
        return env_val.to_lowercase() == "true";
    }

    // Primary: ~/.antigravitycli/config.json
    let mut config_path: Option<std::path::PathBuf> = None;
    if let Ok(home) = std::env::var("HOME") {
        let p = std::path::Path::new(&home).join(".antigravitycli/config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }
    // Fallback: repo-root .antigravitycli/config.json (best-effort: CWD-relative).
    if config_path.is_none() {
        let p = std::path::PathBuf::from(".antigravitycli/config.json");
        if p.exists() {
            config_path = Some(p);
        }
    }

    if let Some(p) = config_path {
        if let Ok(text) = std::fs::read_to_string(&p) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                // bool(data.get("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE", True))
                return match data.get("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE") {
                    Some(v) => py_bool(v),
                    None => true,
                };
            }
        }
    }
    true
}

/// Reproduce Python `bool(x)` truthiness for the JSON value found in config.
fn py_bool(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else if let Some(f) = n.as_f64() {
                f != 0.0
            } else {
                true
            }
        }
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

pub fn audit_grpc_interceptor(input: &Input) -> Output {
    let code = &input.grpc_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Scans for insecure credentials configuration or plain text gRPC options.
    // re.search returns the first match; .group(1) is the captured alternative.
    if let Some(caps) = INSECURE_RE.captures(code) {
        let g1 = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        vulnerable_elements.push(g1.clone());
        flagged_findings.push(format!(
            "gRPC implementation uses an unencrypted wire transmission setup: '{g1}'. \
Establishing unencrypted connections exposes high-performance RPC streams to wiretapping \
and active intercept compromises."
        ));
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GRPC_INTERCEPT".to_string();
        } else {
            status = "WARN_GRPC_INTERCEPT".to_string();
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
    let out = audit_grpc_interceptor(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_grpc_interceptor(&Input {
            file_path: "svc.py".into(),
            grpc_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("channel = grpc.secure_channel(target, creds)");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn insecure_channel_flagged() {
        let o = run("channel = grpc.insecure_channel('localhost:50051')");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GRPC_INTERCEPT");
        assert_eq!(o.vulnerable_elements, vec!["insecure_channel"]);
        assert_eq!(o.risk_score, 75.0);
    }

    #[test]
    fn first_match_only_is_captured() {
        // re.search returns only the FIRST match; group(1) is the alternative.
        let o = run("a = insecure_credentials(); b = insecure_channel()");
        assert_eq!(o.vulnerable_elements, vec!["insecure_credentials"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn empty_code_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
