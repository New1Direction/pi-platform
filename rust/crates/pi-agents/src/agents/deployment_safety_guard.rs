//! Port of `pi_micro_agents/pi_deployment_safety_guard.py`.
//!
//! Specialized gating worker that verifies post-remediation system health and
//! enforces rollback constraints. Behaviour is a line-for-line mirror of the
//! Python original (`PiDeploymentSafetyGuard.verify_deployment_safety`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub deployment_target: String,
    pub post_remediation_code: String,
    #[serde(default = "default_health_check_endpoint")]
    pub health_check_endpoint: String,
}

fn default_health_check_endpoint() -> String {
    "http://localhost:8080/health".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub deployment_allowed: bool,
    pub post_deploy_checks_passed: bool,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `PiDeploymentSafetyGuard.verify_deployment_safety`.
///
/// NOTE: the Python module defines a module-level `is_strict_mode()` that reads
/// `PI_DEPLOYMENT_SAFETY_STRICT_MODE` and a config file, but
/// `verify_deployment_safety` never calls it, so it has no effect on output.
pub fn verify_deployment_safety(input: &Input) -> Output {
    let code = &input.post_remediation_code;
    let mut post_deploy_checks_passed = true;
    let mut risk_score: f64 = 0.0;

    // Heuristic check: ensure no syntax errors or placeholder code remains
    // before releasing to prod.
    let code_lower = code.to_lowercase();
    if code.contains("TODO") || code.contains("FIXME") || code_lower.contains("placeholder") {
        post_deploy_checks_passed = false;
        risk_score = 75.0;
    } else if code_lower.contains("syntaxerror") || code_lower.contains("not defined") {
        post_deploy_checks_passed = false;
        risk_score = 90.0;
    }

    let deployment_allowed = post_deploy_checks_passed;
    let status = if deployment_allowed {
        "DEPLOYED_SUCCESSFULLY".to_string()
    } else {
        "ROLLBACK_TRIGGERED".to_string()
    };

    Output {
        deployment_allowed,
        post_deploy_checks_passed,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = verify_deployment_safety(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        verify_deployment_safety(&Input {
            deployment_target: "prod".into(),
            post_remediation_code: code.into(),
            health_check_endpoint: default_health_check_endpoint(),
        })
    }

    #[test]
    fn clean_code_deploys() {
        let o = run("def add(a, b):\n    return a + b");
        assert!(o.deployment_allowed);
        assert!(o.post_deploy_checks_passed);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "DEPLOYED_SUCCESSFULLY");
    }

    #[test]
    fn placeholder_triggers_rollback() {
        let o = run("# TODO: finish this\nx = 1");
        assert!(!o.deployment_allowed);
        assert!(!o.post_deploy_checks_passed);
        assert_eq!(o.risk_score, 75.0);
        assert_eq!(o.status, "ROLLBACK_TRIGGERED");
    }

    #[test]
    fn placeholder_case_insensitive() {
        // "placeholder" is matched case-insensitively via code.lower().
        let o = run("value = PLACEHOLDER");
        assert!(!o.deployment_allowed);
        assert_eq!(o.risk_score, 75.0);
    }

    #[test]
    fn syntax_error_triggers_higher_risk() {
        let o = run("NameError: foo is not defined");
        assert!(!o.deployment_allowed);
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.status, "ROLLBACK_TRIGGERED");
    }

    #[test]
    fn placeholder_takes_precedence_over_syntaxerror() {
        // Both branches match; the first (placeholder) wins -> 75.0, not 90.0.
        let o = run("TODO fix SyntaxError here");
        assert_eq!(o.risk_score, 75.0);
    }
}
