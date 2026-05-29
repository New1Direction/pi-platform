//! Port of `pi_micro_agents/pi_mock_data_tainting_sentry.py`.
//!
//! Audits mock / fixture files to prevent sensitive data (real-looking
//! credentials, production hosts, private IPs, high-entropy secrets) from
//! leaking. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub data_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub tainted_elements: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict by default; if the env var is set, strict
/// iff it equals (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_MOCK_TAINT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// The five scan patterns, in the exact Python order. None of the Python
// patterns use capturing groups (only `(?:...)`), so `re.findall` returns the
// full match string -> we mirror that with `find_iter`. No lookaround or
// backreferences are used, so each pattern is directly portable to the
// `regex` crate.
static PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"\bAKIA[A-Z0-9]{16}\b").unwrap(),
            "Potential AWS Access Key found",
        ),
        (
            Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b").unwrap(),
            "Potential GitHub Token found",
        ),
        (
            Regex::new(r"\bprod(?:uction)?\.[a-z0-9\-]+\.[a-z]{2,6}\b").unwrap(),
            "Reference to potential live production environment",
        ),
        (
            Regex::new(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            )
            .unwrap(),
            "Internal private IP found",
        ),
        (
            Regex::new(r"\b[a-zA-Z0-9_\-]{32,}\b").unwrap(),
            "High-entropy API key or secret token found",
        ),
    ]
});

pub fn check_mock_tainting(input: &Input) -> Output {
    let content = &input.data_content;
    let mut tainted_elements: Vec<String> = Vec::new();

    let lines = pyutil::splitlines(content);
    for (i, line) in lines.into_iter().enumerate() {
        let idx = i + 1; // Python enumerate(lines, start=1)
        for (pat, desc) in PATTERNS.iter() {
            // For private IPs/API keys, make sure it's not a common standard string.
            // re.findall over a pattern with 0 capture groups -> full matches.
            let matches: Vec<&str> = pat.find_iter(line).map(|mm| mm.as_str()).collect();
            for m in matches {
                let m_lower = m.to_lowercase();
                // Skip common mock phrases or localhost/test strings.
                if ["localhost", "127.0.0.1", "mock", "dummy", "test"]
                    .iter()
                    .any(|x| m_lower.contains(x))
                {
                    continue;
                }
                if m_lower.contains("example") && !m.starts_with("AKIA") {
                    continue;
                }
                // Calculate entropy of matching string.
                // len() in Python counts Unicode code points; mirror with chars().count().
                let m_char_len = m.chars().count();
                if m_char_len >= 16 {
                    let unique_chars: std::collections::HashSet<char> = m.chars().collect();
                    let entropy_ratio = unique_chars.len() as f64 / m_char_len as f64;
                    // High-entropy check (most random keys have high unique character ratio).
                    if entropy_ratio > 0.45 {
                        let prefix: String = m.chars().take(10).collect();
                        tainted_elements.push(format!("Line {idx}: {desc} ('{prefix}...')"));
                        break;
                    }
                } else {
                    tainted_elements.push(format!("Line {idx}: {desc} ('{m}')"));
                    break;
                }
            }
        }
    }

    let mut is_secure = tainted_elements.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_MOCK_TAINT".to_string();
        } else {
            status = "WARN_MOCK_TAINT".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        tainted_elements,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_mock_tainting(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        check_mock_tainting(&Input {
            file_path: "fixture.json".into(),
            data_content: content.into(),
        })
    }

    #[test]
    fn clean_content_passes() {
        let o = run("{\"user\": \"alice\", \"host\": \"localhost\"}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.tainted_elements.is_empty());
    }

    #[test]
    fn aws_key_flagged() {
        let o = run("aws_key = AKIAIOSFODNN7EXAMPLE");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_MOCK_TAINT");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.tainted_elements.len(), 1);
    }

    #[test]
    fn private_ip_flagged() {
        let o = run("server = 192.168.1.42");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(
            o.tainted_elements,
            vec!["Line 1: Internal private IP found ('192.168.1.42')"]
        );
    }

    #[test]
    fn empty_content_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
