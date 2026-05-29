//! Port of `pi_micro_agents/pi_semantic_commit_message_linter.py`.
//!
//! Audits commit messages against the Conventional Commits specification.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub commit_message: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub formatting_errors: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true". When the env var is absent, defaults to
/// strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_COMMIT_LINTER_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Conventional commit pattern:
//   type(scope)!: description
// Mirrors the Python `re.match` pattern exactly. `re.match` anchors at the
// start of the string; we add a leading `^` (Rust's `is_match`/`captures`
// search the whole haystack, so the explicit `^` reproduces `re.match`).
// No lookaround / backreferences are used, so this is a direct port.
static PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\([a-zA-Z0-9_\-/ ]+\))?(!)?:\s+(.+)$",
    )
    .unwrap()
});

pub fn audit_commit_message(input: &Input) -> Output {
    // msg = input_envelope.commit_message.strip()
    let msg = pyutil::strip(&input.commit_message);
    let mut errors: Vec<String> = Vec::new();

    if msg.is_empty() {
        errors.push("Commit message cannot be empty".to_string());
    } else {
        // match = re.match(pattern, msg)
        match PATTERN.captures(msg) {
            None => {
                errors.push(
                    "Commit message does not match Conventional Commits format. \
Expected: '<type>(<scope>): <description>' or '<type>: <description>'. \
Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
                        .to_string(),
                );
            }
            Some(caps) => {
                // description = match.group(3)
                let description = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                // len() in Python counts Unicode code points.
                if description.chars().count() < 5 {
                    errors.push(
                        "Commit description is too short (must be at least 5 characters)"
                            .to_string(),
                    );
                }
            }
        }
    }

    let mut is_secure = errors.is_empty();
    let risk_score = if !is_secure { 50.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_COMMIT_LINTER".to_string();
        } else {
            status = "WARN_COMMIT_LINTER".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        formatting_errors: errors,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_commit_message(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(msg: &str) -> Output {
        audit_commit_message(&Input {
            commit_message: msg.into(),
        })
    }

    #[test]
    fn valid_commit_passes() {
        let o = run("feat(parser): add streaming tokenizer");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.formatting_errors.is_empty());
    }

    #[test]
    fn empty_message_rejected() {
        let o = run("   ");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_COMMIT_LINTER");
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.formatting_errors, vec!["Commit message cannot be empty"]);
    }

    #[test]
    fn bad_format_rejected() {
        let o = run("added a new thing");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_COMMIT_LINTER");
        assert_eq!(o.formatting_errors.len(), 1);
    }

    #[test]
    fn short_description_rejected() {
        let o = run("fix!: bug");
        assert!(!o.is_secure);
        assert_eq!(
            o.formatting_errors,
            vec!["Commit description is too short (must be at least 5 characters)"]
        );
    }
}
