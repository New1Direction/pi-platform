//! Port of `pi_micro_agents/pi_terraform_state_credential_sentry.py`.
//!
//! Audits Terraform source files for hardcoded provider secrets / keys.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub tf_code: String,
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

/// Mirrors the Python regex:
/// `\b(secret_key|access_key|password|token|api_key|client_secret)\s*=\s*["\']([^"\']+)["\']`
/// with `re.IGNORECASE`. Two capture groups, no lookaround/backreferences.
static CRED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(secret_key|access_key|password|token|api_key|client_secret)\s*=\s*["']([^"']+)["']"#,
    )
    .unwrap()
});

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_terraform_credentials(input: &Input) -> Output {
    let code = &input.tf_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        if clean_line.starts_with('#') || clean_line.starts_with("//") {
            continue;
        }

        // Check for patterns of direct credential declarations in tf files
        // e.g., secret_key = "...", access_key = "...", password = "...", token = "..."
        if let Some(caps) = CRED_RE.captures(clean_line) {
            let var_name = caps.get(1).unwrap().as_str();
            let val = caps.get(2).unwrap().as_str();

            // If value is not a standard variable reference (like var.xxx or local.xxx)
            if !val.starts_with("var.") && !val.starts_with("local.") && val.chars().count() > 4 {
                vulnerable_elements.push(format!("Line {idx}"));
                flagged_findings.push(format!(
                    "Line {idx}: Hardcoded credential value assigned to '{var_name}'.\
Statically declaring secrets in IaC configurations exposes credentials to all code repository readers."
                ));
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TERRAFORM_STATE_CREDENTIAL".to_string();
        } else {
            status = "WARN_TERRAFORM_STATE_CREDENTIAL".to_string();
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
    let out = audit_terraform_credentials(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_terraform_credentials(&Input {
            file_path: "main.tf".into(),
            tf_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_var_reference_passes() {
        let o = run("secret_key = var.my_secret");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    fn hardcoded_secret_flagged() {
        let o = run("secret_key = \"AWS_KEY_SCRUBBED\"");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TERRAFORM_STATE_CREDENTIAL");
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    fn comment_lines_skipped() {
        let o = run("# password = \"hunter2supersecret\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn short_value_not_flagged() {
        // value length must be > 4 to flag
        let o = run("token = \"abcd\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
