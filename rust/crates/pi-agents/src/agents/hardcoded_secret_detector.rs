//! Port of `pi_micro_agents/pi_hardcoded_secret_detector.py`.
//!
//! Static analysis agent that detects hardcoded secrets, private keys, and API
//! tokens. Behaviour is a line-for-line mirror of the Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub file_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub flagged_secrets: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

// Standard AWS Access Keys and generic tokens. No lookaround / backrefs, so it
// maps directly onto the `regex` crate. Case-sensitive (Python has no IGNORECASE).
static AWS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPJ)[A-Z0-9]{16}").unwrap());

// Generic credentials assignments (e.g. password = "...", api_key = "...").
// `(?i)` mirrors Python's inline IGNORECASE. Two capture groups -> use
// captures_iter to mirror Python's `findall` returning (var, val) tuples.
static CRED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(password|passwd|secret|api_key|apikey|token|private_key|client_secret)\s*=\s*['"]([^'"]{8,})['"]"#,
    )
    .unwrap()
});

const PLACEHOLDERS: [&str; 7] = [
    "placeholder",
    "your_",
    "insert_",
    "dummy",
    "test_value",
    "123",
    "abc",
];

pub fn scan_hardcoded_secrets(input: &Input) -> Output {
    let content = &input.file_content;
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Regex for SSH/PEM private keys
    let lower_content = content.to_lowercase();
    if lower_content.contains("begin private key") || lower_content.contains("begin rsa private key")
    {
        findings.push("Private key block detected inside text.".to_string());
        risk_score += 50.0;
    }

    // Regex for standard AWS Access Keys and generic tokens
    if AWS_KEY_RE.is_match(content) {
        findings.push("AWS IAM Credentials/Access Key ID detected.".to_string());
        risk_score += 45.0;
    }

    // Generic credentials assignments (e.g. password = "...", api_key = "...")
    for caps in CRED_RE.captures_iter(content) {
        let var = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        // Skip placeholders
        let val_lower = val.to_lowercase();
        if PLACEHOLDERS.iter().any(|p| val_lower.contains(p)) {
            continue;
        }
        findings.push(format!(
            "Hardcoded assignment to sensitive keyword '{var}' found."
        ));
        risk_score += 35.0;
    }

    risk_score = risk_score.min(100.0);
    let is_secure = risk_score < 40.0;
    let status = if !is_secure { "FLAGGED" } else { "PASSED" }.to_string();

    Output {
        is_secure,
        flagged_secrets: findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = scan_hardcoded_secrets(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        scan_hardcoded_secrets(&Input {
            file_path: "f.py".into(),
            file_content: content.into(),
        })
    }

    #[test]
    fn clean_content_passes() {
        let o = run("def add(a, b):\n    return a + b\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.flagged_secrets.is_empty());
    }

    #[test]
    fn private_key_alone_not_enough() {
        // 50.0 -> flagged (>= 40.0)
        let o = run("-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----");
        assert!(!o.is_secure);
        assert_eq!(o.status, "FLAGGED");
        assert_eq!(o.risk_score, 50.0);
        assert_eq!(o.flagged_secrets, vec!["Private key block detected inside text."]);
    }

    #[test]
    fn aws_key_detected() {
        let o = run("aws = 'AKIAIOSFODNN7EXAMPLE'");
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 45.0);
        assert_eq!(o.flagged_secrets, vec!["AWS IAM Credentials/Access Key ID detected."]);
    }

    #[test]
    fn placeholder_credential_skipped() {
        // value contains "123" placeholder -> skipped, stays secure
        let o = run("password = \"changeme123\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }

    #[test]
    fn real_credential_recorded_but_below_threshold() {
        // A single credential scores 35.0 which is < 40.0, so it is still
        // classified PASSED even though the finding is recorded.
        let o = run("api_key = \"sk-livefoobarbaz\"");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 35.0);
        assert_eq!(
            o.flagged_secrets,
            vec!["Hardcoded assignment to sensitive keyword 'api_key' found."]
        );
    }

    #[test]
    fn risk_score_capped_at_100() {
        // private key (50) + aws (45) + real cred (35) = 130 -> capped 100
        let o = run(
            "-----BEGIN PRIVATE KEY-----\nAKIAIOSFODNN7EXAMPLEXX\nclient_secret = \"ZmFrZXNlY3JldA\"\n",
        );
        assert!(!o.is_secure);
        assert_eq!(o.risk_score, 100.0);
        assert_eq!(o.flagged_secrets.len(), 3);
    }
}
