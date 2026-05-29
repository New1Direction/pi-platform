//! Port of `pi_micro_agents/pi_git_secret_entropy_leak_sentry.py`.
//!
//! Specialized Infrastructure micro-agent that analyzes codebase changes for
//! high-entropy password/key strings. Behaviour is a line-for-line mirror of
//! the Python original (`PiGitSecretEntropyLeakSentry.audit_entropy_leaks`).

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

// Mirrors Python: re.findall(r'["\']([a-zA-Z0-9_\-\.\=\+]{16,})["\']', code).
// Single capture group; no lookaround/backrefs, so the regex crate handles it.
static QUOTED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["']([a-zA-Z0-9_\-\.\=\+]{16,})["']"#).unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// strict is `value.lower() == "true"`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors `calculate_shannon_entropy(self, data: str) -> float`.
///
/// Iterates over byte values 0..256, counting occurrences of `chr(x)`. Python's
/// `str.count(chr(x))` counts the unicode code point `x`; we mirror this by
/// counting matching `char`s equal to `char::from_u32(x)` over the full string.
fn calculate_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    // Python `len(data)` is the number of unicode code points.
    let length = data.chars().count() as f64;
    let mut entropy = 0.0_f64;
    for x in 0u32..256 {
        // chr(x) for x in 0..256 is always a valid code point (latin-1 range).
        let ch = char::from_u32(x).unwrap();
        let count = data.chars().filter(|&c| c == ch).count() as f64;
        let p_x = count / length;
        if p_x > 0.0 {
            entropy += -p_x * p_x.log2();
        }
    }
    entropy
}

pub fn audit_entropy_leaks(input: &Input) -> Output {
    let code = &input.code_content;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // re.findall with one capture group -> iterate captures, take group 1.
    for caps in QUOTED_RE.captures_iter(code) {
        let s = caps.get(1).unwrap().as_str();
        let entropy = calculate_shannon_entropy(s);
        // Standard threshold for high-entropy password/private key is ~4.5
        if entropy > 4.5 {
            // Exclude standard safe strings
            let lower = s.to_lowercase();
            let ignored = ["bootstrap", "tailwind", "class", "href", "http", "sha"];
            if ignored.iter().any(|w| lower.contains(w)) {
                continue;
            }
            // Python s[:10] / s[:12] slice by code point; mirror that.
            vulnerable_elements.push(slice_chars(s, 10));
            let s12 = slice_chars(s, 12);
            flagged_findings.push(format!(
                "High-entropy string detected: '{s12}...' (Entropy: {entropy:.2}). \
This pattern frequently indicates embedded secret keys, private credentials, or programmatic passwords."
            ));
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GIT_SECRET_ENTROPY_LEAK".to_string();
        } else {
            status = "WARN_GIT_SECRET_ENTROPY_LEAK".to_string();
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

/// Mirrors Python `s[:n]`: takes up to `n` unicode code points from the start.
fn slice_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_entropy_leaks(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_entropy_leaks(&Input {
            file_path: "f.py".into(),
            code_content: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_code_passes() {
        // Short quoted strings (<16 chars) are never matched.
        let o = run("name = 'hello world'");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn high_entropy_secret_flagged() {
        // A long, high-entropy base64-ish token in quotes.
        let o = run("API_KEY = 'aZ9kQ2mB7xR4tL1pW8vN3cE6'");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GIT_SECRET_ENTROPY_LEAK");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.vulnerable_elements, vec!["aZ9kQ2mB7x".to_string()]);
    }

    #[test]
    fn ignored_keyword_skipped() {
        // Contains "bootstrap" so it is excluded even if high-entropy.
        let o = run("css = 'bootstrap_aZ9kQ2mB7xR4tL1pW8vN3'");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    fn empty_input_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
