//! Port of `pi_micro_agents/pi_constant_time_auditor.py`.
//!
//! Audits cryptographic source code for timing side-channel risks: secret-
//! dependent division/modulo, and secret-dependent `if`/`while` branch or loop
//! conditions. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub source_code: String,
    #[serde(default)]
    pub secrets_context: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_lines: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_CONSTANT_TIME_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Equivalent of Python `re.escape` for the subset of metacharacters the regex
/// crate treats specially. Python's `re.escape` escapes every non-alphanumeric,
/// non-underscore ASCII char; the regex crate accepts a backslash before any of
/// those, so over-escaping (escaping a char that wasn't special) is harmless and
/// preserves the exact set of matched strings.
fn re_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        // Python re.escape escapes everything that isn't [A-Za-z0-9_].
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('\\');
            out.push(ch);
        }
    }
    out
}

pub fn audit_constant_time(input: &Input) -> Output {
    let code = &input.source_code;
    let secrets = &input.secrets_context;
    let mut flagged_lines: Vec<String> = Vec::new();

    // Enumerate lines (1-based, mirroring `enumerate(code.splitlines(), 1)`).
    for (i, line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        // Check for division / modulo on any known secret
        for secret in secrets {
            if line.contains(secret.as_str()) {
                if line.contains('/') || line.contains('%') {
                    flagged_lines.push(format!(
                        "L{idx}: Potential secret-dependent division/modulo on '{secret}': {}",
                        pyutil::strip(line)
                    ));
                }
                let esc = re_escape(secret);
                let if_pat = regex::Regex::new(&format!(r"\bif\s*\(.*{esc}.*\)")).unwrap();
                let while_pat = regex::Regex::new(&format!(r"\bwhile\s*\(.*{esc}.*\)")).unwrap();
                if if_pat.is_match(line) || while_pat.is_match(line) {
                    flagged_lines.push(format!(
                        "L{idx}: Potential secret-dependent branch/loop condition on '{secret}': {}",
                        pyutil::strip(line)
                    ));
                }
            }
        }
    }

    let mut is_secure = flagged_lines.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_TIMING_RISK".to_string();
        } else {
            status = "WARN_TIMING_RISK".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_lines,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_constant_time(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str, secrets: &[&str]) -> Output {
        audit_constant_time(&Input {
            file_path: "f.py".into(),
            source_code: code.into(),
            secrets_context: secrets.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn clean_code_passes() {
        let o = run("x = a + b\nreturn x", &["priv_key"]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_lines.is_empty());
    }

    #[test]
    fn division_on_secret_flagged() {
        let o = run("r = priv_key / 2", &["priv_key"]);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TIMING_RISK");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.flagged_lines.len(), 1);
        assert!(o.flagged_lines[0].contains("division/modulo"));
    }

    #[test]
    fn branch_on_secret_flagged() {
        let o = run("if (secret_d > 0) { foo(); }", &["secret_d"]);
        assert!(!o.is_secure);
        assert_eq!(o.flagged_lines.len(), 1);
        assert!(o.flagged_lines[0].contains("branch/loop condition"));
    }

    #[test]
    fn no_secrets_means_secure() {
        let o = run("if (priv_key > 0) { x = priv_key / 2; }", &[]);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
