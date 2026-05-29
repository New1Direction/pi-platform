//! Port of `pi_micro_agents/pi_request_refactor_plan_verifier.py`.
//!
//! Deterministic micro-agent that verifies refactoring plans contain an impact
//! / dependency analysis and a migration / deployment path. Behaviour is a
//! line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub plan_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub missing_elements: Vec<String>,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff its value is
/// (case-insensitively) "true"; if unset, defaults to strict (`true`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_REQUEST_REFACTOR_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn verify_refactor(input: &Input) -> Output {
    let plan = &input.plan_content;
    let mut missing: Vec<String> = Vec::new();

    // Mirrors the Python `checks` list of (keys, description).
    let checks: [(&[&str], &str); 2] = [
        (
            &["dependency", "impact", "dependencies"],
            "Missing impact analysis or dependency map",
        ),
        (
            &["migration", "deploy"],
            "Missing data, state migration, or deployment details",
        ),
    ];

    let plan_lower = plan.to_lowercase();
    for (keys, desc) in checks.iter() {
        if !keys.iter().any(|k| plan_lower.contains(k)) {
            missing.push((*desc).to_string());
        }
    }

    let mut is_secure = missing.is_empty();

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_REQUEST_REFACTOR".to_string();
        } else {
            status = "WARN_REQUEST_REFACTOR".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        missing_elements: missing,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = verify_refactor(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(plan: &str) -> Output {
        verify_refactor(&Input {
            plan_content: plan.into(),
        })
    }

    #[test]
    fn complete_plan_passes() {
        let o = run("We mapped the dependency impact and a migration deploy plan.");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.missing_elements.is_empty());
    }

    #[test]
    fn missing_both_rejected() {
        let o = run("Just some prose with no relevant keywords.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_REQUEST_REFACTOR");
        assert_eq!(
            o.missing_elements,
            vec![
                "Missing impact analysis or dependency map".to_string(),
                "Missing data, state migration, or deployment details".to_string(),
            ]
        );
    }

    #[test]
    fn missing_migration_only() {
        // Has "impact" (so first check passes) but no migration/deploy.
        let o = run("Impact analysis is complete.");
        assert!(!o.is_secure);
        assert_eq!(
            o.missing_elements,
            vec!["Missing data, state migration, or deployment details".to_string()]
        );
    }
}
