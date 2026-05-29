//! Port of `pi_micro_agents/pi_handoff_checkpoint_sentry.py`.
//!
//! Verifies that handoff documentation contains a clear state and checklist by
//! checking for required keyword headers. Behaviour is a line-for-line mirror
//! of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub handoff_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_missing_items: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is (case-insensitively) something other than "true"; if unset, defaults to
/// strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_HANDOFF_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_handoff(input: &Input) -> Output {
    let content = &input.handoff_content;
    let mut missing: Vec<String> = Vec::new();

    // (keyword, description) mirroring Python's required_headers list/order.
    let required_headers: [(&str, &str); 3] = [
        ("reproduction", "Missing reproduction instructions or scripts"),
        ("next step", "Missing next steps or upcoming items"),
        ("status", "Missing current progress or branch status"),
    ];

    let content_lower = content.to_lowercase();
    for (keyword, desc) in required_headers.iter() {
        if !content_lower.contains(keyword) {
            missing.push((*desc).to_string());
        }
    }

    let mut is_secure = missing.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_HANDOFF".to_string();
        } else {
            status = "WARN_HANDOFF".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        flagged_missing_items: missing,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_handoff(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(content: &str) -> Output {
        audit_handoff(&Input {
            handoff_content: content.into(),
        })
    }

    #[test]
    #[serial]
    fn complete_handoff_passes() {
        // Contains "reproduction", "next step", and "status".
        let o = run(
            "Reproduction: run pytest. Next step: deploy. Status: branch ready.",
        );
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_missing_items.is_empty());
    }

    #[test]
    #[serial]
    fn missing_all_rejected_strict() {
        // Ensure strict mode regardless of ambient env for determinism.
        std::env::set_var("PI_HANDOFF_STRICT_MODE", "true");
        let o = run("nothing relevant here");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_HANDOFF");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(
            o.flagged_missing_items,
            vec![
                "Missing reproduction instructions or scripts".to_string(),
                "Missing next steps or upcoming items".to_string(),
                "Missing current progress or branch status".to_string(),
            ]
        );
        std::env::remove_var("PI_HANDOFF_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn missing_one_warn_when_not_strict() {
        std::env::set_var("PI_HANDOFF_STRICT_MODE", "false");
        // Missing only "next step".
        let o = run("Reproduction steps documented. Status is green.");
        assert!(o.is_secure); // coerced back to true in WARN path
        assert_eq!(o.status, "WARN_HANDOFF");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(
            o.flagged_missing_items,
            vec!["Missing next steps or upcoming items".to_string()]
        );
        std::env::remove_var("PI_HANDOFF_STRICT_MODE");
    }
}
