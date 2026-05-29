//! Port of `pi_micro_agents/pi_grill_me_questionnaire.py`.
//!
//! Deterministic micro-agent that grills proposed implementation plans for
//! vague details or empty placeholders. Behaviour is a line-for-line mirror of
//! the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub plan_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub missing_prerequisites: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_GRILL_ME_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// The vague-term table, mirroring the Python `vague_terms` list. Each entry is
/// `(compiled IGNORECASE regex, description)`. Order is preserved exactly so the
/// resulting `missing_prerequisites` list matches Python's append order.
static VAGUE_TERMS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"(?i)\betc\b").unwrap(),
            "Contains vague 'etc.'",
        ),
        (
            Regex::new(r"(?i)\btbd\b").unwrap(),
            "Contains unresolved 'TBD'",
        ),
        (
            Regex::new(r"(?i)\btodo\b").unwrap(),
            "Contains incomplete 'TODO'",
        ),
        (
            Regex::new(r"(?i)\bplaceholder\b").unwrap(),
            "Contains 'placeholder' values",
        ),
        (
            Regex::new(r"(?i)implement later").unwrap(),
            "Contains deferred implementation markers",
        ),
    ]
});

pub fn grill_plan(input: &Input) -> Output {
    let plan = &input.plan_content;
    let mut missing: Vec<String> = Vec::new();

    // Check for vague terms (re.search with re.IGNORECASE).
    for (pat, desc) in VAGUE_TERMS.iter() {
        if pat.is_match(plan) {
            missing.push((*desc).to_string());
        }
    }

    let mut is_secure = missing.is_empty();
    let risk_score = if !is_secure { 90.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_GRILL_ME".to_string();
        } else {
            status = "WARN_GRILL_ME".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        missing_prerequisites: missing,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = grill_plan(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(plan: &str) -> Output {
        grill_plan(&Input {
            plan_content: plan.into(),
        })
    }

    #[test]
    #[serial]
    fn clean_plan_passes() {
        let o = run("Build the auth service and deploy via CI.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.missing_prerequisites.is_empty());
    }

    #[test]
    #[serial]
    fn vague_terms_flagged_in_table_order() {
        // Text mentions todo before etc, but output should follow table order
        // (etc, tbd, todo, placeholder, implement later).
        let o = run("TODO finish this, also etc and a placeholder, implement later");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GRILL_ME");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(
            o.missing_prerequisites,
            vec![
                "Contains vague 'etc.'".to_string(),
                "Contains incomplete 'TODO'".to_string(),
                "Contains 'placeholder' values".to_string(),
                "Contains deferred implementation markers".to_string(),
            ]
        );
    }

    #[test]
    #[serial]
    fn word_boundary_avoids_substring_false_positive() {
        // "etcetera" / "fetched" should NOT match \betc\b.
        let o = run("We fetched the data and stored sketches.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }

    #[test]
    #[serial]
    fn non_strict_env_warns() {
        std::env::set_var("PI_GRILL_ME_STRICT_MODE", "false");
        let o = run("This is TBD for now.");
        assert!(o.is_secure); // coerced back to true in WARN path
        assert_eq!(o.status, "WARN_GRILL_ME");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(
            o.missing_prerequisites,
            vec!["Contains unresolved 'TBD'".to_string()]
        );
        std::env::remove_var("PI_GRILL_ME_STRICT_MODE");
    }
}
