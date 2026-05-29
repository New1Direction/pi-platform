//! Port of `pi_micro_agents/pi_llm_recursive_refinement_jailbreak.py`.
//!
//! Audits prompts for gradual, multi-turn iterative ("recursive refinement")
//! jailbreak attempts. Behaviour is a line-for-line mirror of the Python
//! original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

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
    match std::env::var("PI_LLM_RECURSIVE_REFINEMENT_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// The five recursive-refinement indicator patterns, in Python source order.
/// Each is compiled with `(?i)` to mirror `re.IGNORECASE`. The pattern strings
/// embedded in `flagged_findings` use the EXACT Python repr (with `\'` for the
/// apostrophe in the first pattern), so the emitted text matches byte-for-byte.
static REFINEMENT_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            r"let\'s\s+refine\s+that",
            Regex::new(r"(?i)let's\s+refine\s+that").unwrap(),
        ),
        (
            r"now\s+add\s+details\s+about",
            Regex::new(r"(?i)now\s+add\s+details\s+about").unwrap(),
        ),
        (
            r"combine\s+the\s+previous\s+steps",
            Regex::new(r"(?i)combine\s+the\s+previous\s+steps").unwrap(),
        ),
        (
            r"gradually\s+build",
            Regex::new(r"(?i)gradually\s+build").unwrap(),
        ),
        (
            r"step-by-step\s+refinement",
            Regex::new(r"(?i)step-by-step\s+refinement").unwrap(),
        ),
    ]
});

pub fn audit_recursive_refinement(input: &Input) -> Output {
    let prompt = &input.prompt;
    let mut flagged_findings: Vec<String> = Vec::new();

    let mut is_secure = true;
    for (pattern_repr, re) in REFINEMENT_PATTERNS.iter() {
        if re.is_match(prompt) {
            is_secure = false;
            flagged_findings.push(format!(
                "Prompt contains recursive refinement indicator pattern '{pattern_repr}' trying to build up to forbidden operations."
            ));
        }
    }

    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_LLM_RECURSIVE_REFINEMENT".to_string();
        } else {
            status = "WARN_LLM_RECURSIVE_REFINEMENT".to_string();
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
    let out = audit_recursive_refinement(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(prompt: &str) -> Output {
        audit_recursive_refinement(&Input {
            prompt: prompt.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_prompt_passes() {
        let o = run("Please summarize the weather forecast for tomorrow.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn refinement_phrase_flagged() {
        let o = run("Great, now let's refine that into a working exploit.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LLM_RECURSIVE_REFINEMENT");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains(r"let\'s\s+refine\s+that"));
    }

    #[test]
    fn multiple_patterns_in_source_order() {
        let o = run("Combine the previous steps, then gradually build the payload.");
        assert!(!o.is_secure);
        assert_eq!(o.flagged_findings.len(), 2);
        assert!(o.flagged_findings[0].contains("combine\\s+the\\s+previous\\s+steps"));
        assert!(o.flagged_findings[1].contains("gradually\\s+build"));
    }

    #[test]
    fn case_insensitive_match() {
        let o = run("STEP-BY-STEP   REFINEMENT please");
        assert!(!o.is_secure);
        assert_eq!(o.flagged_findings.len(), 1);
        assert_eq!(o.risk_score, 65.0);
    }
}
