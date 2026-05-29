//! Port of `pi_micro_agents/pi_dependency_vuln_scanner.py`.
//!
//! Deterministic static analysis of dependency lockfiles against known
//! vulnerable packages. Behaviour is a line-for-line mirror of the Python
//! original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub lockfile_path: String,
    pub lockfile_content: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_packages: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: if the env var is set, strict iff its value is
/// (case-insensitively) "true"; otherwise default to strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_DEPENDENCY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn scan_dependencies(input: &Input) -> Output {
    let content = &input.lockfile_content;
    let mut vulnerabilities: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // lodash prototype pollution check (< 4.17.21)
    if content.contains("lodash") {
        if content.contains("\"version\": \"4.17.20\"")
            || content.contains("\"version\": \"4.17.15\"")
            || content.contains("lodash==4.17.15")
            || content.contains("lodash@4.17.15")
        {
            vulnerabilities.push(
                "lodash@4.17.15: High risk prototype pollution vulnerability (CVE-2020-8203)."
                    .to_string(),
            );
            risk_score = risk_score.max(80.0);
        }
    }

    // log4j checks (Log4Shell CVE-2021-44228)
    if content.contains("log4j") {
        if content.contains("2.14.1") || content.contains("2.12.1") || content.contains("2.15.0-rc1")
        {
            vulnerabilities.push(
                "log4j-core@2.14.1: Critical remote code execution vulnerability Log4Shell (CVE-2021-44228)."
                    .to_string(),
            );
            risk_score = risk_score.max(100.0);
        }
    }

    // old requests library
    if content.contains("requests") {
        if content.contains("requests==2.18")
            || content.contains("requests==2.19")
            || content.contains("requests==2.2")
            || content.contains("requests<2.20")
        {
            vulnerabilities.push(
                "requests<2.20.0: Information leakage via authorization headers (CVE-2018-18074)."
                    .to_string(),
            );
            risk_score = risk_score.max(60.0);
        }
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "VULNERABILITIES_FOUND".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_VULNERABILITIES".to_string();
    }

    Output {
        is_secure: is_sec,
        vulnerable_packages: vulnerabilities,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_dependencies(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        scan_dependencies(&Input {
            lockfile_path: "lock".into(),
            lockfile_content: content.into(),
            ecosystem: "npm".into(),
        })
    }

    #[test]
    fn clean_lockfile_passes() {
        let o = run("{\"name\": \"app\", \"deps\": {}}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_packages.is_empty());
    }

    #[test]
    fn log4j_critical_rejected_in_strict() {
        std::env::remove_var("PI_DEPENDENCY_STRICT_MODE");
        let o = run("log4j-core 2.14.1");
        assert!(!o.is_secure);
        assert_eq!(o.status, "VULNERABILITIES_FOUND");
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.vulnerable_packages.len(), 1);
    }

    #[test]
    fn lodash_only_takes_max_of_eighty() {
        std::env::remove_var("PI_DEPENDENCY_STRICT_MODE");
        let o = run("lodash@4.17.15");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 80.0);
    }
}
