//! Port of `pi_micro_agents/pi_api_auth_hardcoded_token_sentry.py`.
//!
//! Audits API route files / source code for static / hardcoded credentials
//! (tokens, api keys, bearer tokens, client secrets). Behaviour is a
//! line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
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

/// Mirrors the Python module-level regex:
/// `r'\b(token|api_key|bearer|client_secret|api_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']'`
/// with `re.IGNORECASE`. No lookaround / backrefs, so it maps directly.
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(token|api_key|bearer|client_secret|api_token)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{16,})["']"#,
    )
    .unwrap()
});

/// Excluded placeholder substrings (checked against `val.lower()`).
const EXCLUDED: [&str; 5] = ["env.", "process.env", "os.getenv", "config", "default"];

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_hardcoded_tokens(input: &Input) -> Output {
    let code = &input.code_content;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        if clean_line.starts_with('#') || clean_line.starts_with("//") {
            continue;
        }

        // re.search -> first match only.
        if let Some(caps) = TOKEN_RE.captures(clean_line) {
            let var_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            // Exclude environment variable default placeholders or configs.
            let val_lower = val.to_lowercase();
            let is_excluded = EXCLUDED.iter().any(|excluded| val_lower.contains(excluded));
            if !is_excluded {
                vulnerable_elements.push(format!("Line {idx}"));
                flagged_findings.push(format!(
                    "Line {idx}: Static hardcoded key/token '{var_name}' detected. \
Storing access tokens or secret keys directly in application source code facilitates developer-level compromises or secret leaks."
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
            status = "REJECTED_API_AUTH_HARDCODED_TOKEN".to_string();
        } else {
            status = "WARN_API_AUTH_HARDCODED_TOKEN".to_string();
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
    let out = audit_hardcoded_tokens(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_hardcoded_tokens(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn secure_code_passes() {
        let o = run("user = get_user()");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn hardcoded_token_flagged() {
        let o = run("token = \"abcdefghij1234567890\"");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_API_AUTH_HARDCODED_TOKEN");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn comment_line_skipped() {
        let o = run("# api_key = \"abcdefghij1234567890\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn env_placeholder_excluded() {
        // value contains "os.getenv" placeholder substring -> not flagged
        let o = run("api_key = \"os.getenv_FALLBACK_KEY\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
