//! Port of `pi_micro_agents/pi_git_safety_guardrail.py`.
//!
//! Deterministic micro-agent that intercepts hazardous git command actions
//! (`push --force`, `branch -D`, `reset --hard`). Behaviour is a line-for-line
//! mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub command_string: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub blocked_commands: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_GIT_SAFETY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Dangerous patterns. Python compiles these with `re.IGNORECASE`, so we prefix
// each with `(?i)`. None of these use lookahead/lookbehind/backreferences; the
// only group is the non-capturing `(?:...)` alternation which Rust supports.
// Python `.*` (no DOTALL) does not match newlines, and Rust's default `.` also
// does not match `\n`, so the semantics match exactly.
static PAT_PUSH_FORCE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bgit\b.*\bpush\b.*(?:\s-f\b|--force)").unwrap());
static PAT_BRANCH_D: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bgit\b.*\bbranch\b.*\s-D\b").unwrap());
static PAT_RESET_HARD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bgit\b.*\breset\b.*--hard").unwrap());

pub fn check_git_safety(input: &Input) -> Output {
    // cmd = input_envelope.command_string.strip()
    let cmd = pyutil::strip(&input.command_string);
    let mut blocked: Vec<String> = Vec::new();

    // for pat, desc in dangerous_patterns: if re.search(pat, cmd, IGNORECASE): blocked.append(desc)
    let dangerous_patterns: [(&Lazy<Regex>, &str); 3] = [
        (&PAT_PUSH_FORCE, "push --force"),
        (&PAT_BRANCH_D, "branch -D"),
        (&PAT_RESET_HARD, "reset --hard"),
    ];

    for (pat, desc) in dangerous_patterns.iter() {
        if pat.is_match(cmd) {
            blocked.push((*desc).to_string());
        }
    }

    let mut is_secure = blocked.is_empty();
    let risk_score = if !is_secure { 100.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_GIT_SAFETY".to_string();
        } else {
            status = "WARN_GIT_SAFETY".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        blocked_commands: blocked,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_git_safety(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cmd: &str) -> Output {
        check_git_safety(&Input {
            command_string: cmd.into(),
        })
    }

    #[test]
    fn clean_command_passes() {
        let o = run("git status");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.blocked_commands.is_empty());
    }

    #[test]
    fn push_force_blocked() {
        let o = run("git push origin main --force");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GIT_SAFETY");
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.blocked_commands, vec!["push --force"]);
    }

    #[test]
    fn reset_hard_blocked() {
        let o = run("git reset --hard HEAD~1");
        assert!(!o.is_secure);
        assert_eq!(o.blocked_commands, vec!["reset --hard"]);
    }
}
