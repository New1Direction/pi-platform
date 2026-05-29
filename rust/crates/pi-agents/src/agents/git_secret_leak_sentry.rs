//! Port of `pi_micro_agents/pi_git_secret_leak_sentry.py`.
//!
//! Audits files for hardcoded secrets, private keys, and high-entropy
//! credentials. Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub file_content: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// The ordered (pattern, label) list mirroring `secret_patterns` in Python.
///
/// All patterns are plain regex (no lookaround / backreferences), so they are
/// supported as-is by the Rust `regex` crate. The non-capturing group `(?:...)`
/// in the mnemonic pattern is supported.
static SECRET_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----").unwrap(),
            "RSA Private Key",
        ),
        (
            Regex::new(r"-----BEGIN\s+PRIVATE\s+KEY-----").unwrap(),
            "Generic Private Key",
        ),
        (
            Regex::new(r"sk_live_[a-zA-Z0-9]{24}").unwrap(),
            "Stripe Live API Key",
        ),
        (
            Regex::new(
                r"amzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .unwrap(),
            "AWS MWS Client Token",
        ),
        (
            Regex::new(r"AIzaSy[a-zA-Z0-9_-]{33}").unwrap(),
            "Google API Key",
        ),
        (
            Regex::new(r#"aws_secret_access_key\s*=\s*["']?[a-zA-Z0-9/+=]{40}["']?"#).unwrap(),
            "AWS Secret Access Key",
        ),
        (
            Regex::new(r"(?:[a-zA-Z]+\s+){11}[a-zA-Z]+").unwrap(),
            "Potential Mnemonic Seed Phrase (12 words)",
        ),
    ]
});

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var. If set, strict iff its lowercase value is
/// exactly "true". If the env var is unset, Python then probes a config file on
/// disk (`~/.antigravitycli/config.json` or a path relative to the module). For
/// parity under the harness we read the env var first; when unset we default to
/// `true`, matching Python's behaviour when no config file is present (the
/// `data.get(..., True)` default and the final `return True`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_GIT_SECRET_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Returns the byte index that is `n` chars before `pos`, clamped at 0 — the
/// equivalent of Python `content[max(0, pos - 100): ...]` where slicing is by
/// (Unicode code point) index. We replicate code-point semantics so multi-byte
/// content windows match Python exactly.
fn char_window(content: &str, start_char: usize, end_char: usize) -> String {
    // start_char/end_char are computed in Python char (code point) units.
    content
        .chars()
        .skip(start_char)
        .take(end_char.saturating_sub(start_char))
        .collect()
}

/// Number of Unicode code points in a byte-prefix of `content` ending at the
/// given byte offset — used to convert regex byte offsets to Python char
/// indices.
fn byte_to_char_index(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset].chars().count()
}

pub fn audit_secrets(input: &Input) -> Output {
    let content = &input.file_content;
    let mut flagged_findings: Vec<String> = Vec::new();

    let mut _is_secure = true;
    for (pattern, label) in SECRET_PATTERNS.iter() {
        // re.search -> first match anywhere in the string.
        if let Some(m) = pattern.find(content) {
            let matched_str = m.as_str();
            if *label == "Potential Mnemonic Seed Phrase (12 words)" {
                // Python: content[max(0, match.start() - 100): min(len, match.end() + 100)].lower()
                // match.start()/match.end() are CHAR indices in Python.
                let start_char = byte_to_char_index(content, m.start());
                let end_char = byte_to_char_index(content, m.end());
                let total_chars = content.chars().count();
                let win_start = start_char.saturating_sub(100);
                let win_end = std::cmp::min(total_chars, end_char + 100);
                let surrounding = char_window(content, win_start, win_end).to_lowercase();
                if ["seed", "mnemonic", "bip39", "key", "secret", "private"]
                    .iter()
                    .any(|x| surrounding.contains(x))
                {
                    _is_secure = false;
                    flagged_findings.push(format!(
                        "File contains a pattern matching '{label}' with high confidence. \
Hardcoding secrets in repositories exposes systems to total compromise."
                    ));
                }
            } else {
                _is_secure = false;
                // matched_str[:15] in Python slices by char (code point).
                let prefix: String = matched_str.chars().take(15).collect();
                flagged_findings.push(format!(
                    "File contains a pattern matching '{label}' ('{prefix}...'). \
Exposing private credentials in source code enables simple unauthorized resource access."
                ));
            }
        }
    }

    // Python recomputes is_secure from the findings list (overriding the loop's value).
    let mut is_secure = flagged_findings.is_empty();
    let risk_score = if !is_secure { 95.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GIT_SECRET".to_string();
        } else {
            status = "WARN_GIT_SECRET".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_secrets(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(content: &str) -> Output {
        audit_secrets(&Input {
            file_path: "f.txt".into(),
            file_content: content.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_content_passes() {
        std::env::remove_var("PI_GIT_SECRET_STRICT_MODE");
        let o = run("def add(a, b):\n    return a + b\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn rsa_private_key_flagged() {
        std::env::remove_var("PI_GIT_SECRET_STRICT_MODE");
        let o = run("-----BEGIN RSA PRIVATE KEY-----\nMIIabc...\n-----END RSA PRIVATE KEY-----");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GIT_SECRET");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("RSA Private Key"));
    }

    #[test]
    #[serial]
    fn mnemonic_needs_context() {
        std::env::remove_var("PI_GIT_SECRET_STRICT_MODE");
        // 12 plain English words with no secret context -> NOT flagged.
        let plain = run("the quick brown fox jumps over the lazy dog and then runs");
        assert!(plain.is_secure);
        assert_eq!(plain.status, "PASSED");

        // Same shape but with the word "seed" in context -> flagged.
        let with_ctx = run("seed: the quick brown fox jumps over the lazy dog and then runs");
        assert!(!with_ctx.is_secure);
        assert!(with_ctx.flagged_findings[0].contains("Mnemonic"));
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_GIT_SECRET_STRICT_MODE", "false");
        let o = run("-----BEGIN PRIVATE KEY-----\nstuff\n-----END PRIVATE KEY-----");
        assert!(o.is_secure); // coerced back to true in WARN mode
        assert_eq!(o.status, "WARN_GIT_SECRET");
        assert_eq!(o.risk_score, 95.0);
        std::env::remove_var("PI_GIT_SECRET_STRICT_MODE");
    }
}
