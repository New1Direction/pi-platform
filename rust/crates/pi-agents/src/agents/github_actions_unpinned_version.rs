//! Port of `pi_micro_agents/pi_github_actions_unpinned_version.py`.
//!
//! Audits GitHub Action workflow steps for third-party actions that are pinned
//! to a tag/branch instead of a full commit SHA. Behaviour is a line-for-line
//! mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub yaml_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_elements: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors the Python `re.search(r'uses:\s*([...])@([...])', clean_line)`.
static USES_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"uses:\s*([a-zA-Z0-9_\-\./]+)@([a-zA-Z0-9_\-\.]+)").unwrap());

/// Mirrors the Python `re.match(r'^[a-fA-F0-9]{40}$', ref)` — a full 40-char
/// hex commit SHA. The anchors make `is_match` equivalent to `re.match` here.
static SHA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{40}$").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set, in which case
/// it is strict only when the value equals (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_github_actions(input: &Input) -> Output {
    let code = &input.yaml_code;
    let mut vulnerable_elements: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    for (i, raw_line) in pyutil::splitlines(code).into_iter().enumerate() {
        let idx = i + 1;
        let clean_line = pyutil::strip(raw_line);
        // Look for lines containing "uses:"
        if clean_line.starts_with("uses:") || clean_line.contains("uses:") {
            // Action usage format: uses: owner/repo@tagOrSha or owner/repo/path@tagOrSha
            if let Some(caps) = USES_RE.captures(clean_line) {
                let action_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let ref_ = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                // Ignore local actions (e.g. uses: ./.github/actions/something)
                if action_name.starts_with("./") {
                    continue;
                }

                // Check if ref is a full 40-character hex commit SHA
                let is_sha = SHA_RE.is_match(ref_);
                if !is_sha {
                    vulnerable_elements.push(format!("Line {idx}"));
                    flagged_findings.push(format!(
                        "Line {idx}: Action '{action_name}' is pinned to tag or branch '{ref_}' instead of a secure full commit SHA. \
Unpinned action dependencies allow upstream maintainers or attackers modifying tags to execute arbitrary code in workflows."
                    ));
                }
            }
        }
    }

    let mut is_secure = vulnerable_elements.is_empty();
    let risk_score = if !is_secure { 70.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_GITHUB_ACTIONS_UNPINNED".to_string();
        } else {
            status = "WARN_GITHUB_ACTIONS_UNPINNED".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_elements,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_github_actions(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(yaml: &str) -> Output {
        audit_github_actions(&Input {
            file_path: "ci.yml".into(),
            yaml_code: yaml.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn sha_pinned_passes() {
        // 40-char hex SHA -> secure
        let o = run("      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_elements.is_empty());
    }

    #[test]
    fn tag_pinned_flagged() {
        let o = run("      - uses: actions/checkout@v4");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_GITHUB_ACTIONS_UNPINNED");
        assert_eq!(o.risk_score, 70.0);
        assert_eq!(o.vulnerable_elements, vec!["Line 1"]);
    }

    #[test]
    fn local_action_ignored() {
        let o = run("      - uses: ./.github/actions/build@main");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.vulnerable_elements.is_empty());
    }
}
