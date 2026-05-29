//! Port of `pi_micro_agents/pi_to_prd_validator.py`.
//!
//! Deterministic micro-agent that checks PRDs for defined objectives and
//! functional scope boundaries. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub prd_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub failed_sections: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TO_PRD_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn validate_prd(input: &Input) -> Output {
    let content = &input.prd_content;
    let mut failed: Vec<String> = Vec::new();

    // (keywords, section_name) mirroring the Python `sections` list.
    let sections: [(&[&str], &str); 4] = [
        (&["objective", "goal"], "Objective or Goal section"),
        (&["non-goal", "out of scope"], "Non-Goals section"),
        (
            &["requirement", "specification", "spec"],
            "Requirements or Functional Specifications section",
        ),
        (
            &["verification", "validation", "success criteria"],
            "Verification or Success Criteria section",
        ),
    ];

    let lower = content.to_lowercase();
    for (keywords, section_name) in sections.iter() {
        // Python: if not any(kw in content.lower() for kw in keywords)
        if !keywords.iter().any(|kw| lower.contains(kw)) {
            failed.push((*section_name).to_string());
        }
    }

    let mut is_secure = failed.is_empty();
    let risk_score = if !is_secure { 85.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TO_PRD".to_string();
        } else {
            status = "WARN_TO_PRD".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        failed_sections: failed,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = validate_prd(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        validate_prd(&Input {
            prd_content: content.into(),
        })
    }

    #[test]
    fn complete_prd_passes() {
        let o = run(
            "# Objective\nGoal here.\n## Non-Goals\nOut of scope.\n## Requirements\nspec.\n## Verification\nSuccess criteria.",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.failed_sections.is_empty());
    }

    #[test]
    fn missing_sections_rejected_in_strict() {
        // Default (no env) is strict mode.
        let o = run("Just some text with no required headings.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TO_PRD");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.failed_sections.len(), 4);
    }

    #[test]
    fn partial_prd_flags_only_missing() {
        // Has objective + requirements, missing non-goals + verification.
        let o = run("Objective: build it. Requirements: must work.");
        assert!(!o.is_secure);
        assert_eq!(
            o.failed_sections,
            vec![
                "Non-Goals section".to_string(),
                "Verification or Success Criteria section".to_string(),
            ]
        );
    }
}
