//! Port of `pi_micro_agents/pi_readme_validator.py`.
//!
//! Deterministic micro-agent that checks a README.md file for critical
//! sections (Prerequisites, Installation, Usage). Behaviour is a line-for-line
//! mirror of the Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub readme_content: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub missing_sections: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_README_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// expected_sections from the Python source. Each section name maps to a set of
// patterns; the section is "found" if any line matches any pattern.
// All patterns use re.IGNORECASE -> `(?i)`. `^` anchors to the start of each
// (per-line) haystack, matching Python's `re.search` applied to each line.
static PAT_PREREQUISITE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^#+\s+.*prerequisite").unwrap());
static PAT_REQUIREMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^#+\s+.*requirement").unwrap());
static PAT_INSTALL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^#+\s+.*install").unwrap());
static PAT_USAGE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^#+\s+.*usage").unwrap());
static PAT_GETTING_STARTED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^#+\s+.*getting\s+started").unwrap());

pub fn validate_readme(input: &Input) -> Output {
    let content = &input.readme_content;
    let mut missing_sections: Vec<String> = Vec::new();

    // Sections we expect to find in a complete README (case insensitive heading
    // match). Mirrors the Python `expected_sections` list in order.
    let expected_sections: [(&str, &[&Lazy<Regex>]); 3] = [
        ("prerequisites", &[&PAT_PREREQUISITE, &PAT_REQUIREMENT]),
        ("installation", &[&PAT_INSTALL]),
        ("usage", &[&PAT_USAGE, &PAT_GETTING_STARTED]),
    ];

    let lines = pyutil::splitlines(content);
    for (section_name, patterns) in expected_sections.iter() {
        let mut found = false;
        for line in lines.iter() {
            if patterns.iter().any(|pat| pat.is_match(line)) {
                found = true;
                break;
            }
        }
        if !found {
            missing_sections.push((*section_name).to_string());
        }
    }

    let mut is_secure = missing_sections.is_empty();
    let risk_score = if !is_secure { 40.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_README".to_string();
        } else {
            status = "WARN_README".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        missing_sections,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = validate_readme(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str) -> Output {
        validate_readme(&Input {
            readme_content: content.into(),
        })
    }

    #[test]
    fn complete_readme_passes() {
        let o = run("# Prerequisites\n## Installation\n### Usage\n");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.missing_sections.is_empty());
    }

    #[test]
    fn missing_sections_rejected() {
        let o = run("# My Project\nSome text without headers.");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_README");
        assert_eq!(o.risk_score, 40.0);
        assert_eq!(
            o.missing_sections,
            vec![
                "prerequisites".to_string(),
                "installation".to_string(),
                "usage".to_string()
            ]
        );
    }

    #[test]
    fn requirement_and_getting_started_aliases() {
        let o = run("# Requirements\n## How to install it\n## Getting Started");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.missing_sections.is_empty());
    }
}
