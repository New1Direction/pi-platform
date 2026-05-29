//! Port of `pi_micro_agents/pi_triage_bug_labels.py`.
//!
//! Deterministic micro-agent that parses bug tracebacks/error logs and suggests
//! triage labels (component + severity). Behaviour is a line-for-line mirror of
//! the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub log_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub recommended_labels: Vec<String>,
    pub component: String,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_TRIAGE_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn triage_bug(input: &Input) -> Output {
    let log = &input.log_content;
    let mut labels: Vec<String> = Vec::new();
    let mut component = "unknown".to_string();

    // Parse component keywords (order matters; first match wins via break).
    let components: [(&str, &str); 8] = [
        ("solidity", "web3-solidity"),
        ("solana", "web3-solana"),
        ("anchor", "web3-solana"),
        ("circom", "zero-knowledge"),
        ("docker", "devops-docker"),
        ("kubernetes", "devops-k8s"),
        ("jwt", "api-auth"),
        ("auth", "api-auth"),
    ];
    let log_lower = log.to_lowercase();
    for (key, name) in components.iter() {
        if log_lower.contains(key) {
            component = (*name).to_string();
            break;
        }
    }

    // Parse severity.
    if log_lower.contains("critical")
        || log_lower.contains("fatal")
        || log_lower.contains("syntaxerror")
    {
        labels.push("severity-critical".to_string());
    } else if log_lower.contains("warning") || log_lower.contains("deprecated") {
        labels.push("severity-warning".to_string());
    } else {
        labels.push("severity-normal".to_string());
    }

    if component != "unknown" {
        labels.push(component.clone());
    }

    let mut is_secure = !labels.iter().any(|l| l == "severity-critical");

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TRIAGE".to_string();
        } else {
            status = "WARN_TRIAGE".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        recommended_labels: labels,
        component,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = triage_bug(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(log: &str) -> Output {
        triage_bug(&Input {
            log_content: log.into(),
        })
    }

    #[test]
    fn clean_normal_log_passes() {
        let o = run("just a routine info message");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.component, "unknown");
        assert_eq!(o.recommended_labels, vec!["severity-normal"]);
    }

    #[test]
    fn critical_solidity_rejected_in_strict() {
        // Default (no env) -> strict mode.
        std::env::remove_var("PI_TRIAGE_STRICT_MODE");
        let o = run("FATAL error in Solidity contract compilation");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TRIAGE");
        assert_eq!(o.component, "web3-solidity");
        assert_eq!(
            o.recommended_labels,
            vec!["severity-critical", "web3-solidity"]
        );
    }

    #[test]
    fn warning_jwt_component() {
        let o = run("Warning: deprecated JWT usage detected");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.component, "api-auth");
        assert_eq!(o.recommended_labels, vec!["severity-warning", "api-auth"]);
    }
}
