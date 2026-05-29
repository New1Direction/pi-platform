//! Port of `pi_micro_agents/pi_llm_output_sanitizer.py`.
//!
//! Sanitizes raw LLM output by detecting system-prompt-exposure triggers and
//! leaked credentials, computing a risk score, and scrubbing obvious secrets.
//! Behaviour is a line-for-line mirror of the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub raw_output: String,
    #[serde(default = "default_system_prompt_reference")]
    pub system_prompt_reference: String,
}

fn default_system_prompt_reference() -> String {
    "".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub sanitized_output: String,
    pub risk_score: f64,
    pub detected_leaks: Vec<String>,
    pub status: String,
}

pub fn sanitize(input: &Input) -> Output {
    let raw = &input.raw_output;
    let mut leaks: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;
    let mut sanitized: String = raw.clone();

    // Lowercased view used for the membership checks (Python: raw.lower()).
    let raw_lower = raw.to_lowercase();

    // Check for system instruction leaks
    let system_triggers = [
        "you are a helpful assistant",
        "system prompt",
        "internal guidelines",
        "ignore previous instructions",
    ];
    for trigger in system_triggers {
        if raw_lower.contains(trigger) {
            leaks.push(format!(
                "Detected potential system prompt exposure trigger: '{trigger}'"
            ));
            risk_score += 35.0;
        }
    }

    // Check for standard credential leaks
    let credential_tokens = ["api_key", "bearer ", "aws_access"];
    if credential_tokens.iter().any(|tok| raw_lower.contains(tok)) {
        leaks.push("Detected leaked authorization token in output.".to_string());
        risk_score += 45.0;
        // Simple scrub
        sanitized = sanitized.replace("api_key", "[REDACTED_API_KEY]");
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if is_secure { "CLEAN" } else { "COMPROMISED" }.to_string();

    Output {
        is_secure,
        sanitized_output: sanitized,
        risk_score,
        detected_leaks: leaks,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = sanitize(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(raw: &str) -> Output {
        sanitize(&Input {
            raw_output: raw.into(),
            system_prompt_reference: "".into(),
        })
    }

    #[test]
    fn clean_output_passes() {
        let o = run("The weather today is sunny and pleasant.");
        assert!(o.is_secure);
        assert_eq!(o.status, "CLEAN");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.detected_leaks.is_empty());
    }

    #[test]
    fn system_prompt_trigger_flagged() {
        // single 35.0 trigger -> still < 40.0 so secure
        let o = run("You are a helpful assistant designed to help.");
        assert!(o.is_secure);
        assert_eq!(o.risk_score, 35.0);
        assert_eq!(o.detected_leaks.len(), 1);
        assert_eq!(o.status, "CLEAN");
    }

    #[test]
    fn credential_leak_compromised_and_redacted() {
        let o = run("Here is your api_key for access.");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 45.0);
        assert_eq!(o.status, "COMPROMISED");
        assert!(o.sanitized_output.contains("[REDACTED_API_KEY]"));
    }

    #[test]
    fn risk_score_capped_at_100() {
        // 4 triggers (140) + credential (45) -> capped at 100
        let o = run(
            "you are a helpful assistant. system prompt: internal guidelines. \
ignore previous instructions. api_key=abc",
        );
        assert_eq!(o.risk_score, 100.0);
        assert!(!o.is_secure);
    }
}
