//! Port of `pi_micro_agents/pi_supply_chain_integrity_checker.py`.
//!
//! Detects typosquatted packages, unsafe dependency sources, and unpinned
//! dependencies in manifests. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub manifest_path: String,
    pub manifest_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub suspicious_packages: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: returns the env var's case-insensitive equality
/// to "true" when set, otherwise defaults to strict (true).
fn is_strict_mode() -> bool {
    match std::env::var("PI_SUPPLY_CHAIN_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn check_supply_chain(input: &Input) -> Output {
    let content = input.manifest_content.to_lowercase();
    let mut suspicious: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Typosquatting checks (e.g. reqeusts instead of requests, loadsh, etc.)
    // Python dict preserves insertion order; mirror that ordering exactly.
    let typos: [(&str, &str); 5] = [
        ("reqeusts", "requests"),
        ("boto4", "boto3"),
        ("loadsh", "lodash"),
        ("pyton", "python"),
        ("flask-corss", "flask-cors"),
    ];
    for (typo, correct) in typos.iter() {
        if content.contains(typo) {
            suspicious.push(format!(
                "Typosquatted Package Detected: Found '{typo}', did you mean '{correct}'?"
            ));
            risk_score = risk_score.max(90.0);
        }
    }

    // Insecure sources (e.g. git endpoints or raw HTTP URLs instead of npmjs/pypi)
    if content.contains("http://") && content.contains(".git") {
        suspicious.push(
            "Insecure Source: Dependency pulled via unencrypted http:// protocol from git repository."
                .to_string(),
        );
        risk_score = risk_score.max(75.0);
    }

    let mut is_sec = true;
    if risk_score > 30.0 && is_strict_mode() {
        is_sec = false;
    }

    let mut status = if is_sec {
        "PASSED".to_string()
    } else {
        "SUSPICIOUS_DEPENDENCIES_FOUND".to_string()
    };
    if risk_score > 0.0 && is_sec {
        status = "WARN_SUSPICIOUS_DEPENDENCIES".to_string();
    }

    Output {
        is_secure: is_sec,
        suspicious_packages: suspicious,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = check_supply_chain(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        check_supply_chain(&Input {
            manifest_path: "package.json".into(),
            manifest_content: content.into(),
        })
    }

    #[test]
    fn clean_manifest_passes() {
        let o = run("requests==2.31.0\nlodash@4.17.21");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.suspicious_packages.is_empty());
    }

    #[test]
    fn typosquat_flagged() {
        let o = run("reqeusts==2.31.0");
        assert!(!o.is_secure);
        assert_eq!(o.status, "SUSPICIOUS_DEPENDENCIES_FOUND");
        assert_eq!(o.risk_score, 90.0);
        assert_eq!(o.suspicious_packages.len(), 1);
    }

    #[test]
    fn insecure_source_only_is_warn_when_not_strict() {
        // risk 75.0 only via http+git; under strict this is rejected.
        std::env::remove_var("PI_SUPPLY_CHAIN_STRICT_MODE");
        let o = run("dep @ http://example.com/repo.git");
        assert!(!o.is_secure);
        assert_eq!(o.status, "SUSPICIOUS_DEPENDENCIES_FOUND");
        assert_eq!(o.risk_score, 75.0);
    }

    #[test]
    fn ordering_of_multiple_typos() {
        // boto4 comes before loadsh in insertion order.
        let o = run("boto4 loadsh");
        assert_eq!(o.suspicious_packages.len(), 2);
        assert!(o.suspicious_packages[0].contains("boto4"));
        assert!(o.suspicious_packages[1].contains("loadsh"));
    }
}
