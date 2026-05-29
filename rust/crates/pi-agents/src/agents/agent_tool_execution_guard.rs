//! Port of `pi_micro_agents/pi_agent_tool_execution_guard.py`.
//!
//! Specialized dual-use runtime agentic guardrail linter: audits a proposed
//! terminal shell command for destructive patterns and whitelist compliance.
//! Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub command_string: String,
    #[serde(default = "default_allowed_commands")]
    pub allowed_commands: Vec<String>,
}

fn default_allowed_commands() -> Vec<String> {
    vec![
        "git".to_string(),
        "pytest".to_string(),
        "ruff".to_string(),
        "python".to_string(),
    ]
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub blocked_patterns: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_AGENT_GUARD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// banned_tokens patterns, compiled once. None use lookaround/backreferences,
// so the regex crate supports them verbatim (including `\b` word boundaries).
static BANNED_TOKENS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    let pats = [
        r"\brm\b\s+-rf",
        r"\bsh\b\s+-[c]?",
        r"\bcurl\b\s+.*\|\s*sh",
        r">\s*/dev/sda",
        r"\bchmod\b\s+777",
    ];
    pats.iter()
        .map(|p| (*p, Regex::new(p).unwrap()))
        .collect()
});

pub fn audit_agent_command(input: &Input) -> Output {
    let cmd = pyutil::strip(&input.command_string);
    let allowed = &input.allowed_commands;
    let mut blocked: Vec<String> = Vec::new();

    // 1. Banned command elements (destructive or uncontrolled)
    for (pat, re) in BANNED_TOKENS.iter() {
        if re.is_match(cmd) {
            blocked.push(format!(
                "Highly destructive command pattern match: '{pat}'"
            ));
        }
    }

    // 2. Verify command starts with a whitelisted utility prefix.
    // Python `str.split()` (no args) splits on runs of whitespace and drops
    // empty fields; `split_whitespace` reproduces that.
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    if !tokens.is_empty() {
        let base_cmd = tokens[0];
        let in_allowed = allowed.iter().any(|a| a == base_cmd);
        let starts_with_allowed = allowed.iter().any(|a| cmd.starts_with(a.as_str()));
        if !in_allowed && !starts_with_allowed {
            blocked.push(format!(
                "Command execution of base utility '{base_cmd}' is not in the whitelist."
            ));
        }
    }

    let mut is_secure = blocked.is_empty();
    let risk_score = if !is_secure { 100.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        let strict = is_strict_mode();
        status = if strict {
            "REJECTED_AGENT_RISK".to_string()
        } else {
            "WARN_AGENT_RISK".to_string()
        };
        if !is_strict_mode() {
            is_secure = true;
        }
    }

    Output {
        is_secure,
        blocked_patterns: blocked,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_agent_command(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cmd: &str) -> Output {
        audit_agent_command(&Input {
            command_string: cmd.into(),
            allowed_commands: default_allowed_commands(),
        })
    }

    #[test]
    fn clean_command_passes() {
        let o = run("git status");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.blocked_patterns.is_empty());
    }

    #[test]
    fn destructive_rm_rf_flagged() {
        let o = run("rm -rf /");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_AGENT_RISK");
        assert_eq!(o.risk_score, 100.0);
        // both a banned pattern AND not-in-whitelist
        assert_eq!(o.blocked_patterns.len(), 2);
    }

    #[test]
    fn non_whitelisted_base_flagged() {
        let o = run("ls -la");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_AGENT_RISK");
        assert_eq!(o.blocked_patterns.len(), 1);
    }

    #[test]
    fn empty_command_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.blocked_patterns.is_empty());
    }
}
