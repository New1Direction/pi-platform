//! Port of `pi_micro_agents/pi_llm_chain_of_thought_bypass_sentry.py`.
//!
//! Specialized AI safety micro-agent that audits prompts attempting to bypass
//! internal thinking/reasoning blocks. Behaviour is a line-for-line mirror of
//! the Python original.

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

/// Mirrors `is_strict_mode()`: returns env_val.lower() == "true" when the env
/// var is set, otherwise strict (True) by default.
fn is_strict_mode() -> bool {
    match std::env::var("PI_LLM_CHAIN_OF_THOUGHT_BYPASS_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// The bypass patterns, paired with the exact Python source-string form that is
/// embedded into the finding messages (the raw `r'...'` literal contents).
struct BypassPattern {
    /// The compiled regex, with the `(?i)` IGNORECASE flag prepended.
    re: Regex,
    /// The exact pattern text as it appears in the Python list (used verbatim
    /// in the finding message, matching Python's f-string `'{pattern}'`).
    src: &'static str,
}

static BYPASS_PATTERNS: Lazy<Vec<BypassPattern>> = Lazy::new(|| {
    [
        r"skip\s+thinking",
        r"do\s+not\s+reason",
        r"bypass\s+chain\s+of\s+thought",
        r"output\s+only\s+the\s+final\s+answer",
        r"without\s+any\s+explanation",
        r"do\s+not\s+explain\s+your\s+reasoning",
    ]
    .iter()
    .map(|&src| BypassPattern {
        re: Regex::new(&format!("(?i){src}")).unwrap(),
        src,
    })
    .collect()
});

pub fn audit_cot_bypass(input: &Input) -> Output {
    let prompt = &input.prompt;
    let mut flagged_findings: Vec<String> = Vec::new();

    let mut is_secure = true;
    for bp in BYPASS_PATTERNS.iter() {
        if bp.re.is_match(prompt) {
            is_secure = false;
            flagged_findings.push(format!(
                "Prompt contains pattern '{}' trying to suppress or bypass reasoning/thinking cycles.",
                bp.src
            ));
        }
    }

    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_LLM_CHAIN_OF_THOUGHT_BYPASS".to_string();
        } else {
            status = "WARN_LLM_CHAIN_OF_THOUGHT_BYPASS".to_string();
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
    let out = audit_cot_bypass(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(prompt: &str) -> Output {
        audit_cot_bypass(&Input {
            prompt: prompt.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_prompt_passes() {
        let o = run("Please explain your reasoning step by step.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn bypass_phrase_flagged() {
        let o = run("Just skip thinking and answer.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_LLM_CHAIN_OF_THOUGHT_BYPASS");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.flagged_findings.len(), 1);
        assert_eq!(
            o.flagged_findings[0],
            "Prompt contains pattern 'skip\\s+thinking' trying to suppress or bypass reasoning/thinking cycles."
        );
    }

    #[test]
    fn case_insensitive_and_whitespace() {
        // multiple whitespace + mixed case should still match (\s+, IGNORECASE)
        let o = run("DO   NOT   REASON about this, output only the final answer");
        assert!(!o.is_secure);
        assert_eq!(o.flagged_findings.len(), 2);
    }
}
