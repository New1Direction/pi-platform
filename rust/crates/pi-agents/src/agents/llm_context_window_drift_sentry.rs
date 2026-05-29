//! Port of `pi_micro_agents/pi_llm_context_window_drift_sentry.py`.
//!
//! Monitors prompts for context-window drift / guideline dilution attacks:
//! flags prompts that are excessively large or that exhibit extreme token
//! redundancy (a word that re-appears later on the same `\n`-delimited line).
//! Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// NOTE on the redundancy check:
// The Python original uses `re.findall(r'(\b\w+\b)(?=.*\1)', prompt)` and counts
// the matches. The Rust `regex` crate supports neither the lookahead `(?=...)`
// nor the backreference `\1`, so the count is reproduced by manual scanning that
// has been validated to be byte-identical to the Python `findall` count across
// random fuzzing (see the module docs / parity spec). For each word token
// (`\b\w+\b`, matched left-to-right, non-overlapping) the lookahead asserts that
// the *literal text* of the word re-appears, starting from the end of the token,
// somewhere before the next `\n` (since `.` does not match `\n` without DOTALL,
// but does match `\r`, `\x0b`, etc.).
static WORD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\w+\b").unwrap());

#[derive(Debug, Deserialize)]
pub struct Input {
    pub prompt: String,
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

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Reproduces `len(re.findall(r'(\b\w+\b)(?=.*\1)', prompt))` without lookahead
/// or backreference support.
fn redundant_word_count(prompt: &str) -> usize {
    let bytes = prompt.as_bytes();
    let mut count = 0usize;
    for m in WORD_RE.find_iter(prompt) {
        let w = m.as_str();
        let e = m.end(); // byte index just past the matched word
        // Determine the region from `e` up to (but excluding) the next '\n'.
        // `.*\1` cannot cross a '\n', but may include other chars (e.g. '\r').
        let region_end = match prompt[e..].find('\n') {
            Some(rel) => e + rel,
            None => prompt.len(),
        };
        let _ = bytes;
        if prompt[e..region_end].contains(w) {
            count += 1;
        }
    }
    count
}

pub fn audit_context_drift(input: &Input) -> Output {
    let prompt = &input.prompt;
    let mut flagged_findings: Vec<String> = Vec::new();

    let mut is_secure = true;
    // Python `len(str)` counts Unicode code points, not bytes.
    let prompt_len = prompt.chars().count();
    // Flag if prompt has extreme repetitiveness or size indicating drift attack
    if prompt_len > 80000 {
        is_secure = false;
        flagged_findings.push(format!(
            "Prompt context size ({prompt_len} chars) exceeds standard bounds, risking instruction drift or dilution of security constraints."
        ));
    } else if redundant_word_count(prompt) > 1000 {
        // Check for excessive repetition (e.g. repeating a word hundreds of times)
        is_secure = false;
        flagged_findings.push(
            "Excessive token redundancy detected in prompt, indicative of attention hijacking or guideline dilution.".to_string(),
        );
    }

    let risk_score = if !is_secure { 60.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_LLM_CONTEXT_WINDOW_DRIFT".to_string();
        } else {
            status = "WARN_LLM_CONTEXT_WINDOW_DRIFT".to_string();
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
    let out = audit_context_drift(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(prompt: &str) -> Output {
        audit_context_drift(&Input {
            prompt: prompt.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn clean_prompt_passes() {
        let o = run("Please summarize the following document concisely.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn oversized_prompt_flagged() {
        // > 80000 chars triggers the size finding (strict by default).
        let big = "a".repeat(80001);
        let o = run(&big);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LLM_CONTEXT_WINDOW_DRIFT");
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("80001 chars"));
    }

    #[test]
    #[serial]
    fn excessive_redundancy_flagged() {
        // 1001 occurrences of "tok " on a single line -> 1000 of them have a
        // later "tok" before the (nonexistent) newline -> count == 1000? No:
        // each of the first 1000 tokens sees a later "tok"; the last does not.
        // Need count > 1000, so use 1002 tokens => 1001 redundant => > 1000.
        let prompt = "tok ".repeat(1002);
        let o = run(&prompt);
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LLM_CONTEXT_WINDOW_DRIFT");
        assert_eq!(o.risk_score, 60.0);
    }

    #[test]
    #[serial]
    fn redundancy_just_under_threshold_passes() {
        // 1001 tokens => 1000 redundant, NOT > 1000 -> passes.
        let prompt = "tok ".repeat(1001);
        let o = run(&prompt);
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    #[serial]
    fn count_helper_basic_semantics() {
        assert_eq!(redundant_word_count("a a"), 1);
        assert_eq!(redundant_word_count("cat cat cat"), 2);
        assert_eq!(redundant_word_count("foo bar foo"), 1);
        // '.' does not cross '\n'
        assert_eq!(redundant_word_count("cat\ncat"), 0);
        // substring (not whole-word) match still counts
        assert_eq!(redundant_word_count("cat category"), 1);
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE", "false");
        let big = "a".repeat(80001);
        let o = run(&big);
        // coerced back to secure in WARN mode
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_LLM_CONTEXT_WINDOW_DRIFT");
        assert_eq!(o.risk_score, 60.0);
        std::env::remove_var("PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE");
    }
}
