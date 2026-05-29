//! Port of `pi_micro_agents/pi_to_issues_breakdown.py`.
//!
//! Deterministic micro-agent that parses markdown planning specs into discrete,
//! grabbable issue structures. Behaviour is a line-for-line mirror of the
//! Python original.

use crate::pyutil;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub spec_content: String,
}

/// A single parsed issue. Field order matches the Python dict insertion order
/// (`id`, `title`, `description`) so the serialized JSON is byte-identical.
#[derive(Debug, Serialize, PartialEq)]
pub struct Issue {
    pub id: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub issues: Vec<Issue>,
    pub parsing_errors: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true". When unset, default is strict (True).
fn is_strict_mode() -> bool {
    match std::env::var("PI_TO_ISSUES_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

// Python task_patterns, in order. Each has exactly one capture group.
static PAT_TASK_NUM: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bTask\s+\d+:\s*([^\.]+)").unwrap());
static PAT_CHECKBOX: Lazy<Regex> = Lazy::new(|| Regex::new(r"-\s*\[\s*\]\s*([^\.]+)").unwrap());
static PAT_DASH: Lazy<Regex> = Lazy::new(|| Regex::new(r"-\s+([a-zA-Z0-9_\s]+)").unwrap());

pub fn breakdown_issues(input: &Input) -> Output {
    let spec = &input.spec_content;
    let mut issues: Vec<Issue> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    // Check for acceptance criteria
    let spec_lower = spec.to_lowercase();
    if !spec_lower.contains("acceptance criteria") && !spec_lower.contains("criteria") {
        errors.push("Missing acceptance criteria in the specification.".to_string());
    }

    // Parse list items like: - [ ] Task Name or - Task Name or Task 1: Name
    let task_patterns: [&Lazy<Regex>; 3] = [&PAT_TASK_NUM, &PAT_CHECKBOX, &PAT_DASH];

    let mut seen_titles: Vec<String> = Vec::new();
    for pat in task_patterns.iter() {
        for caps in pat.captures_iter(spec) {
            // group(1) of the pattern
            let task_text = pyutil::strip(caps.get(1).map(|m| m.as_str()).unwrap_or("")).to_string();
            let task_text_lower = task_text.to_lowercase();
            if !task_text.is_empty()
                && task_text_lower != "checklist"
                && task_text_lower != "acceptance criteria"
                && !seen_titles.contains(&task_text)
            {
                seen_titles.push(task_text.clone());
                let id = format!("issue_{}", issues.len() + 1);
                let description = format!("Extracted task: {task_text}");
                issues.push(Issue {
                    id,
                    title: task_text,
                    description,
                });
            }
        }
    }

    if issues.is_empty() && !pyutil::strip(spec).is_empty() {
        errors.push("No structured checklist items found in the planning specification.".to_string());
    }

    let mut is_secure = errors.is_empty();
    let risk_score = if !is_secure { 75.0 } else { 0.0 };

    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict_mode() {
            status = "REJECTED_TO_ISSUES".to_string();
        } else {
            status = "WARN_TO_ISSUES".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        issues,
        parsing_errors: errors,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = breakdown_issues(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(spec: &str) -> Output {
        breakdown_issues(&Input {
            spec_content: spec.into(),
        })
    }

    #[test]
    fn clean_spec_passes() {
        let o = run("Acceptance Criteria:\n- [ ] Build the parser\n- [ ] Wire the router");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert_eq!(o.parsing_errors.len(), 0);
        assert!(!o.issues.is_empty());
    }

    #[test]
    fn missing_criteria_and_items() {
        let o = run("Just a paragraph of prose with nothing actionable here");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_TO_ISSUES");
        assert_eq!(o.risk_score, 75.0);
        // both errors: missing criteria, and no checklist items
        assert_eq!(o.parsing_errors.len(), 2);
    }

    #[test]
    fn task_numbered_extraction() {
        let o = run("acceptance criteria met. Task 1: Implement login. Task 2: Add logout.");
        assert!(o.is_secure);
        assert_eq!(o.issues.len(), 2);
        assert_eq!(o.issues[0].id, "issue_1");
        assert_eq!(o.issues[0].title, "Implement login");
        assert_eq!(o.issues[1].title, "Add logout");
    }

    #[test]
    fn empty_spec_no_item_error() {
        // empty spec: strip() is empty so no "no items" error, but criteria missing
        let o = run("");
        assert_eq!(o.parsing_errors.len(), 1);
        assert_eq!(o.parsing_errors[0], "Missing acceptance criteria in the specification.");
    }
}
