//! Port of `pi_micro_agents/pi_grpc_wire_protocol_insecure_sentry.py`.
//!
//! Audits gRPC client channels for insecure (non-TLS) transport, e.g.
//! `grpc.insecure_channel(...)` or `credentials=None`. Behaviour is a
//! line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub code_content: String,
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

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff its
/// lowercased value equals "true"; otherwise (unset) defaults to strict.
fn is_strict_mode() -> bool {
    match std::env::var("PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_grpc_insecure(input: &Input) -> Output {
    let code = &input.code_content;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find gRPC channel creation, e.g. grpc.insecure_channel or insecure_channel
    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        if clean_line.contains("insecure_channel") || clean_line.contains("credentials=None") {
            vulnerable_elements.push(format!("Line {idx}"));
            flagged_findings.push(format!(
                "Line {idx}: Insecure gRPC channel definition detected: '{clean_line}'. \
Unencrypted gRPC communication permits network-level wire interception or eavesdropping."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GRPC_WIRE_PROTOCOL_INSECURE".to_string();
        } else {
            status = "WARN_GRPC_WIRE_PROTOCOL_INSECURE".to_string();
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
    let out = audit_grpc_insecure(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_grpc_insecure(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("channel = grpc.secure_channel(addr, creds)");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn insecure_channel_flagged() {
        let o = run("channel = grpc.insecure_channel('localhost:50051')");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GRPC_WIRE_PROTOCOL_INSECURE");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn credentials_none_flagged() {
        let o = run("ch = grpc.secure_channel(addr, credentials=None)");
        assert!(!o.is_secure);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
        assert_eq!(o.risk_score, 80.0);
    }
}
