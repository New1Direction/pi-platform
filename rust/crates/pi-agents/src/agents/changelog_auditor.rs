//! Port of `pi_micro_agents/pi_changelog_auditor.py`.
//!
//! Deterministic micro-agent that verifies the target version's CHANGELOG.md
//! entry structure. Behaviour is a line-for-line mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub changelog_content: String,
    pub target_version: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub format_issues: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict by default. If `PI_CHANGELOG_STRICT_MODE`
/// is set, strict iff its value (lowercased) equals "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_CHANGELOG_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Mirrors Python `str.lstrip('v')`: strip ALL leading 'v' characters.
fn lstrip_v(s: &str) -> &str {
    s.trim_start_matches('v')
}

// Mirrors Python `re.match(r"^\d+\.", line)`. `re.match` anchors at the start
// of the string; `find` against a `^`-anchored pattern reproduces that since
// each `line` has no embedded newline.
static NUMBERED_BULLET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d+\.").unwrap());

pub fn audit_changelog(input: &Input) -> Output {
    let content = &input.changelog_content;
    // version = input_envelope.target_version.strip().lstrip('v')
    let version = lstrip_v(pyutil::strip(&input.target_version));
    let mut issues: Vec<String> = Vec::new();

    // Look for headers containing the version, e.g., '## [1.2.3]', '## v1.2.3', '## 1.2.3'
    // version_header_pattern = rf"^##\s+\[?v?{escaped_version}\]?"
    let escaped_version = regex::escape(version);
    let version_header_pattern = format!(r"^##\s+\[?v?{escaped_version}\]?");
    let version_header_re = Regex::new(&version_header_pattern).unwrap();

    let lines = pyutil::splitlines(content);
    let mut found_version_header = false;
    let mut version_header_line_idx: i64 = -1;

    for (idx, line) in lines.iter().enumerate() {
        if version_header_re.is_match(line) {
            found_version_header = true;
            version_header_line_idx = idx as i64;
            break;
        }
    }

    if !found_version_header {
        issues.push(format!(
            "Target version '{}' entry not found in CHANGELOG",
            input.target_version
        ));
    } else {
        // Check if there are descriptive bullet points below the target version
        // header and before the next major section (any line starting with '##').
        let mut bullet_points_found = false;
        let start = (version_header_line_idx + 1) as usize;
        for idx in start..lines.len() {
            let line = pyutil::strip(lines[idx]);
            if line.starts_with("##") {
                break;
            }
            if line.starts_with('-') || line.starts_with('*') || NUMBERED_BULLET_RE.is_match(line) {
                bullet_points_found = true;
                break;
            }
        }

        if !bullet_points_found {
            issues.push(format!(
                "No release notes/bullet points found under target version '{}' header",
                input.target_version
            ));
        }
    }

    let mut is_secure = issues.is_empty();
    let risk_score = if !is_secure { 45.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_CHANGELOG".to_string();
        } else {
            status = "WARN_CHANGELOG".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        format_issues: issues,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_changelog(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str, version: &str) -> Output {
        audit_changelog(&Input {
            changelog_content: content.into(),
            target_version: version.into(),
        })
    }

    #[test]
    fn clean_entry_with_bullets_passes() {
        let o = run("## [1.2.3]\n- Added a thing\n- Fixed a thing\n", "1.2.3");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.format_issues.is_empty());
    }

    #[test]
    fn missing_version_is_rejected() {
        let o = run("## [1.0.0]\n- Initial release\n", "2.0.0");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CHANGELOG");
        assert_eq!(o.risk_score, 45.0);
        assert_eq!(
            o.format_issues,
            vec!["Target version '2.0.0' entry not found in CHANGELOG"]
        );
    }

    #[test]
    fn header_without_bullets_is_rejected() {
        // version header present but no bullet points before next '##'
        let o = run("## v1.2.3\n## 1.0.0\n- old\n", "v1.2.3");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_CHANGELOG");
        assert_eq!(
            o.format_issues,
            vec!["No release notes/bullet points found under target version 'v1.2.3' header"]
        );
    }

    #[test]
    fn numbered_bullet_counts_as_release_notes() {
        let o = run("## 1.2.3\n1. did a thing\n", "1.2.3");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
    }
}
