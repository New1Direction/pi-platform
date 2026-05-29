//! Port of `pi_micro_agents/pi_api_owasp_scanner.py`.
//!
//! Scans OpenAPI/Swagger specifications for broken authentication, insecure path
//! parameters, and unrestricted resource consumption (OWASP API Top 10).
//! Behaviour is a line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub api_path: String,
    pub schema_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub owasp_violations: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff its value is
/// (case-insensitively) "true"; if unset, defaults to strict (`true`).
fn is_strict_mode() -> bool {
    match std::env::var("PI_API_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn scan_api(input: &Input) -> Output {
    let content = input.schema_content.to_lowercase();
    let mut violations: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // API1:2023 Broken Object Level Authorization (BOLA) or Broken Authentication
    if !content.contains("security:") && !content.contains("\"security\"") {
        violations.push(
            "OWASP API2 - Broken Authentication: API endpoints missing security/auth schemes."
                .to_string(),
        );
        risk_score = risk_score.max(85.0);
    }

    // API3:2023 Broken Object Property Level Authorization (BOPLA) or SQL injection points in paths
    if content.contains("{id}") || content.contains("{user_id}") {
        if !content.contains("pattern:") && !content.contains("\"pattern\"") {
            violations.push(
                "OWASP API3 - Insecure Path Parameters: User-supplied identifiers lack regex input sanitization validation."
                    .to_string(),
            );
            risk_score = risk_score.max(60.0);
        }
    }

    // API4:2023 Unrestricted Resource Consumption
    if !content.contains("limit") && !content.contains("page") && !content.contains("size") {
        violations.push(
            "OWASP API4 - Unrestricted Resource Consumption: Pagination or rate-limit configurations missing on collection endpoints."
                .to_string(),
        );
        risk_score = risk_score.max(70.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_API_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_API_COMPLIANCE".to_string();
    }

    Output {
        is_secure: is_sec,
        owasp_violations: violations,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_api(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(schema: &str) -> Output {
        scan_api(&Input {
            api_path: "openapi.yaml".into(),
            schema_content: schema.into(),
        })
    }

    #[test]
    fn clean_schema_passes() {
        // Has security, has limit/page/size, no {id}/{user_id} path params.
        let o = run("security:\n  - apiKey: []\nparameters:\n  limit: 10\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.owasp_violations.is_empty());
    }

    #[test]
    fn missing_security_fails_strict() {
        // No security -> API2 (85.0). Has "limit" so API4 not triggered.
        let o = run("paths:\n  /items:\n    get:\n      parameters:\n        limit: 5\n");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_API_COMPLIANCE");
        assert_eq!(o.risk_score, 85.0);
        assert_eq!(o.owasp_violations.len(), 1);
    }

    #[test]
    fn insecure_path_param_only_warns() {
        // Has security (no API2), has {id} without pattern (API3=60), has "size" (no API4).
        // risk_score 60 > 30 with strict -> FAILED.
        let o = run("security:\n  - oauth: []\npaths:\n  /users/{id}:\n    parameters:\n      size: 1\n");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 60.0);
        assert_eq!(o.owasp_violations.len(), 1);
        assert!(o.owasp_violations[0].contains("OWASP API3"));
    }

    #[test]
    fn path_param_with_pattern_ok() {
        let o = run("security:\n  - oauth: []\npaths:\n  /users/{id}:\n    parameters:\n      pattern: '^[0-9]+$'\n      size: 1\n");
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.status, "PASSED");
    }
}
