//! Port of `pi_micro_agents/pi_firewall_rule_auditor.py`.
//!
//! Detects exposed administrative interfaces (SSH, RDP) or database ports open
//! to the public internet. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub rules_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub open_ports: Vec<i64>,
    pub issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_FIREWALL_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_firewall(input: &Input) -> Output {
    let content = input.rules_content.to_lowercase();
    let mut issues: Vec<String> = Vec::new();
    let mut open_ports: Vec<i64> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Port 22 SSH Check
    if content.contains("port: 22") || content.contains("port=22") || content.contains("ssh") {
        if content.contains("0.0.0.0/0") || content.contains("any") || content.contains("allow all")
        {
            open_ports.push(22);
            issues.push(
                "Exposed SSH Access: Administrative interface (SSH port 22) open to public internet."
                    .to_string(),
            );
            risk_score = risk_score.max(90.0);
        }
    }

    // Port 3389 RDP Check
    if content.contains("port: 3389") || content.contains("port=3389") || content.contains("rdp") {
        if content.contains("0.0.0.0/0") || content.contains("any") || content.contains("allow all")
        {
            open_ports.push(3389);
            issues.push(
                "Exposed RDP Access: Administrative interface (RDP port 3389) open to public internet."
                    .to_string(),
            );
            risk_score = risk_score.max(95.0);
        }
    }

    // Port 27017 MongoDB Check
    if content.contains("port: 27017")
        || content.contains("port=27017")
        || content.contains("mongodb")
    {
        if content.contains("0.0.0.0/0") || content.contains("any") || content.contains("allow all")
        {
            open_ports.push(27017);
            issues.push(
                "Exposed Database Port: NoSQL storage engine (MongoDB port 27017) accessible to anyone."
                    .to_string(),
            );
            risk_score = risk_score.max(85.0);
        }
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "FAILED_FIREWALL_COMPLIANCE".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_FIREWALL".to_string();
    }

    Output {
        is_secure: is_sec,
        open_ports,
        issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_firewall(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        audit_firewall(&Input {
            rules_content: content.into(),
        })
    }

    #[test]
    fn clean_config_passes() {
        let o = run("allow tcp port 443 from 10.0.0.0/8");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.open_ports.is_empty());
    }

    #[test]
    fn exposed_ssh_flagged() {
        // strict mode default -> FAILED
        std::env::remove_var("PI_FIREWALL_STRICT_MODE");
        let o = run("allow ssh from 0.0.0.0/0");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FAILED_FIREWALL_COMPLIANCE");
        assert_eq!(o.open_ports, vec![22]);
        assert_eq!(o.risk_score, 90.0);
    }

    #[test]
    fn multiple_ports_take_max_risk() {
        std::env::remove_var("PI_FIREWALL_STRICT_MODE");
        let o = run("rdp port=3389 mongodb any");
        assert!(!o.is_secure);
        assert_eq!(o.open_ports, vec![3389, 27017]);
        assert_eq!(o.risk_score, 95.0);
    }
}
