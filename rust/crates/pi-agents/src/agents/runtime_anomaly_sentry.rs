//! Port of `pi_micro_agents/pi_runtime_anomaly_sentry.py`.
//!
//! Flags runtime metric drift, unauthorized execution binaries, or suspicious
//! outbound connections in production. Behaviour is a line-for-line mirror of
//! the Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub metrics_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub anomalies_detected: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_RUNTIME_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_runtime(input: &Input) -> Output {
    let content = input.metrics_content.to_lowercase();
    let mut anomalies: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // CPU / memory spikes
    if content.contains("cpu_spike") || content.contains("cpu: 99%") || content.contains("oom_killed")
    {
        anomalies.push(
            "Resource Exhaustion: Runtime logs indicate critical CPU threshold breaches or container OOM terminations."
                .to_string(),
        );
        risk_score = risk_score.max(70.0);
    }

    // High error rates
    if content.contains("error_rate: 45%") || content.contains("5xx_errors: high") {
        anomalies.push(
            "Uncontrolled Fault Rate: High density of 5xx HTTP exceptions suggests dynamic system instability."
                .to_string(),
        );
        risk_score = risk_score.max(80.0);
    }

    // Unauthorized outbound network connection attempts
    if content.contains("unauthorized outbound")
        || content.contains("suspicious connection to")
        || content.contains("sh: ")
        || content.contains("cmd.exe")
    {
        anomalies.push(
            "Suspicious Shell Execution: Runtime detected unauthorized bash/cmd spawn queries or unexpected ports."
                .to_string(),
        );
        risk_score = risk_score.max(95.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "ANOMALIES_DETECTED".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_ANOMALIES".to_string();
    }

    Output {
        is_secure: is_sec,
        anomalies_detected: anomalies,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_runtime(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        audit_runtime(&Input {
            metrics_content: content.into(),
        })
    }

    #[test]
    fn clean_metrics_pass() {
        let o = run("cpu: 12%\nmemory: 40%\nerror_rate: 0%");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.anomalies_detected.is_empty());
    }

    #[test]
    fn shell_execution_flagged() {
        // case-insensitive: "CMD.EXE" matches "cmd.exe" after lowercasing
        let o = run("Detected SUSPICIOUS CONNECTION TO 10.0.0.1 spawning CMD.EXE");
        assert!(!o.is_secure);
        assert_eq!(o.status, "ANOMALIES_DETECTED");
        assert_eq!(o.risk_score, 95.0);
        assert_eq!(o.anomalies_detected.len(), 1);
    }

    #[test]
    fn cpu_spike_takes_max_risk() {
        // multiple anomalies; risk_score is the max across matches
        let o = run("cpu_spike detected\nerror_rate: 45%");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.anomalies_detected.len(), 2);
        assert_eq!(o.status, "ANOMALIES_DETECTED");
    }
}
