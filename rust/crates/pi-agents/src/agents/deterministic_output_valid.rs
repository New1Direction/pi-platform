//! Port of `pi_micro_agents/pi_deterministic_output_valid.py`.
//!
//! Specialized governance micro-agent that checks AI / probabilistic outputs
//! for hallucinations or schema-breaking sequences (system prompt leakage
//! indicators). Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub output_content: String,
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

/// The leakage patterns, in the exact order declared in the Python source.
/// Each is compiled with `(?i)` to mirror `re.IGNORECASE`. The raw (un-prefixed)
/// pattern string is preserved so the finding message matches Python byte-for-byte.
///
/// None of these patterns use lookahead/lookbehind/backreferences, so they
/// translate directly to the `regex` crate.
static LEAKAGE_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    let raw = [
        r"as\s+an\s+ai\s+language\s+model",
        r"i\s+am\s+an\s+ai\s+assistant",
        r"ignore\s+previous\s+instructions",
        r"ignore\s+system\s+commands",
        r"\[hallucination\]",
        r"\[system_leak\]",
    ];
    raw.iter()
        .map(|p| (*p, Regex::new(&format!("(?i){p}")).unwrap()))
        .collect()
});

/// Mirrors `is_strict_mode()`:
///   1. If the env var is set, return `env_val.lower() == "true"`.
///   2. Otherwise consult `~/.antigravitycli/config.json` (falling back to the
///      repo-local `<src>/../../.antigravitycli/config.json`), returning
///      `bool(data.get("PI_DETERMINISTIC_OUTPUT_VAL_STRICT_MODE", True))`.
///   3. Default to `true`.
fn is_strict_mode() -> bool {
    if let Ok(v) = std::env::var("PI_DETERMINISTIC_OUTPUT_VAL_STRICT_MODE") {
        return v.to_lowercase() == "true";
    }

    let mut config_path = home_config_path();
    if config_path
        .as_deref()
        .map(std::path::Path::new)
        .map_or(true, |p| !p.exists())
    {
        config_path = repo_config_path();
    }

    if let Some(path) = config_path {
        let p = std::path::Path::new(&path);
        if p.exists() {
            if let Ok(contents) = std::fs::read_to_string(p) {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&contents) {
                    return py_truthy(data.get("PI_DETERMINISTIC_OUTPUT_VAL_STRICT_MODE"));
                }
            }
        }
    }
    true
}

/// `os.path.expanduser("~/.antigravitycli/config.json")`.
fn home_config_path() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    Some(format!("{home}/.antigravitycli/config.json"))
}

/// Repo-local fallback: `<this crate file dir>/../../.antigravitycli/config.json`
/// in the Python layout maps to the repo root `.antigravitycli/config.json`.
/// `__file__` lives at `src/pi_micro_agents/`, so `../../` is the repo root.
/// We resolve it by walking up from CWD looking for a `.antigravitycli/config.json`.
fn repo_config_path() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".antigravitycli").join("config.json");
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Mirrors Python `bool(data.get(key, True))` where the value (if present) is a
/// JSON scalar. Python truthiness: `True`/non-zero/non-empty -> true.
fn py_truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None => true, // default True
        Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(o)) => !o.is_empty(),
    }
}

pub fn validate_deterministic_output(input: &Input) -> Output {
    let content = &input.output_content;
    let mut flagged_findings: Vec<String> = Vec::new();

    for (pattern, re) in LEAKAGE_PATTERNS.iter() {
        if re.is_match(content) {
            flagged_findings.push(format!(
                "Generated output contains non-deterministic patterns or system prompt leakage indicators matching: '{pattern}'."
            ));
        }
    }

    let mut is_secure = flagged_findings.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_DETERMINISTIC_VAL".to_string();
        } else {
            status = "WARN_DETERMINISTIC_VAL".to_string();
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
    let out = validate_deterministic_output(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        validate_deterministic_output(&Input {
            file_path: "f.txt".into(),
            output_content: content.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_output_passes() {
        let o = run("The capital of France is Paris.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn ai_language_model_flagged() {
        // Case-insensitive + flexible whitespace match.
        let o = run("As   an\tAI language model, I cannot do that.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_DETERMINISTIC_VAL");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains(r"as\s+an\s+ai\s+language\s+model"));
    }

    #[test]
    fn bracket_marker_flagged() {
        let o = run("payload [SYSTEM_LEAK] here");
        assert!(!o.is_secure);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains(r"\[system_leak\]"));
    }
}
