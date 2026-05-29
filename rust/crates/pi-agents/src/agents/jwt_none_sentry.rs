//! Port of `pi_micro_agents/pi_api_auth_jwt_none_algorithm_sentry.py`.
//!
//! Audits JWT decoders for the insecure `none` algorithm / disabled signature
//! verification. Behaviour is a line-for-line mirror of the Python original.

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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_API_AUTH_JWT_NONE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit(input: &Input) -> Output {
    let code = &input.code_content;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        if clean_line.contains("jwt.decode") || clean_line.contains("jwt.verify") {
            if !clean_line.contains("algorithms")
                || clean_line.to_lowercase().contains("none")
                || clean_line.contains("verify=False")
                || clean_line.contains("verify=false")
            {
                vulnerable_elements.push(format!("Line {idx}"));
                flagged_findings.push(format!(
                    "Line {idx}: Potential insecure JWT decoding configuration: '{clean_line}'. \
Allowing the 'none' signature algorithm or bypassing signature verification allows attackers to spoof token signatures."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_API_AUTH_JWT_NONE".to_string();
        } else {
            status = "WARN_API_AUTH_JWT_NONE".to_string();
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
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("token = jwt.decode(t, key, algorithms=['HS256'])");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    fn none_algorithm_flagged() {
        let o = run("jwt.decode(t, key, algorithms=['none'])");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_API_AUTH_JWT_NONE");
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn missing_algorithms_flagged() {
        let o = run("jwt.decode(t, key)");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 95.0);
    }
}
