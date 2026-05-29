//! Port of `pi_micro_agents/pi_pubsub_topic_naming_auditor.py`.
//!
//! Audits GCP Pub/Sub topic and subscription naming structures against GCP
//! standards and conventions. Behaviour is a line-for-line mirror of the
//! Python original.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub topic_name: String,
    #[serde(default)]
    pub subscription_names: Vec<String>,
    #[serde(default)]
    pub project_id: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_valid: bool,
    pub topic_issues: Vec<String>,
    pub subscription_issues: Vec<String>,
    pub naming_score: f64,
    pub risk_score: f64,
    pub status: String,
}

/// Number of Unicode code points, mirroring Python `len(str)`.
fn py_len(s: &str) -> usize {
    s.chars().count()
}

/// Mirror of Python `s[0].isalpha()` (returns `false` for empty `s`).
///
/// Python `str.isalpha()` is Unicode-aware (the Unicode "Alphabetic"
/// derived property). Rust's `char::is_alphabetic` uses the same property,
/// so accented letters / CJK return `true` while digits, superscripts and
/// punctuation return `false`, matching CPython.
fn first_char_isalpha(s: &str) -> bool {
    match s.chars().next() {
        Some(c) => c.is_alphabetic(),
        None => false,
    }
}

/// Exact replication of Python `re.match(r"^<class>+$", s)` for a character
/// predicate `class_ok`.
///
/// Python's `$` (non-multiline) anchors at the end of the string *or* just
/// before a single trailing `\n`. The Rust `regex` crate's `$` does not, so we
/// scan manually to stay byte-for-byte faithful:
///   * at most one trailing `\n` is permitted (and consumed);
///   * the remaining string must be non-empty (the `+` quantifier);
///   * every remaining character must satisfy `class_ok`.
fn py_match_class<F: Fn(char) -> bool>(s: &str, class_ok: F) -> bool {
    // Allow exactly one trailing '\n' (Python `$` semantics).
    let body = if s.ends_with('\n') {
        &s[..s.len() - 1]
    } else {
        s
    };
    if body.is_empty() {
        // `+` requires at least one matching character.
        return false;
    }
    body.chars().all(class_ok)
}

/// Topic/subscription character class: `[a-zA-Z0-9-_.~+%]`.
fn topic_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '%')
}

/// Project-id rest class: `[a-z0-9-]`.
fn project_rest_char_ok(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '-')
}

/// Exact replication of Python `re.match(r"^[a-z][a-z0-9-]*$", s)`.
fn project_id_matches(s: &str) -> bool {
    // Allow exactly one trailing '\n' (Python `$` semantics).
    let body = if s.ends_with('\n') {
        &s[..s.len() - 1]
    } else {
        s
    };
    let mut chars = body.chars();
    match chars.next() {
        Some(c) if matches!(c, 'a'..='z') => {}
        _ => return false, // first char must be [a-z] (also handles empty)
    }
    chars.all(project_rest_char_ok)
}

pub fn audit(input: &Input) -> Output {
    let topic_name = &input.topic_name;
    let subscription_names = &input.subscription_names;
    let project_id = &input.project_id;

    let mut topic_issues: Vec<String> = Vec::new();
    let mut subscription_issues: Vec<String> = Vec::new();
    let mut naming_score: f64 = 100.0;

    // 1. Topic name validation
    // Rule 1: Length must be 3-255 characters
    let topic_len = py_len(topic_name);
    if !(3 <= topic_len && topic_len <= 255) {
        topic_issues.push("Topic name must be between 3 and 255 characters long.".to_string());
        naming_score -= 25.0;
    }

    // Rule 2: Must start with a letter
    if topic_name.is_empty() || !first_char_isalpha(topic_name) {
        topic_issues.push("Topic name must start with a letter.".to_string());
        naming_score -= 25.0;
    }

    // Rule 3: Valid characters only
    if !py_match_class(topic_name, topic_char_ok) {
        topic_issues.push("Topic name contains invalid characters.".to_string());
        naming_score -= 25.0;
    }

    // Rule 4: Must not start with 'goog' prefix
    if topic_name.to_lowercase().starts_with("goog") {
        topic_issues
            .push("Topic name cannot start with the reserved 'goog' prefix.".to_string());
        naming_score -= 25.0;
    }

    // Convention: Warn on test/temp/demo in production/naming
    let topic_lower = topic_name.to_lowercase();
    if ["test", "temp", "demo"].iter().any(|w| topic_lower.contains(w)) {
        topic_issues
            .push("Topic name contains placeholder keywords (test, temp, demo).".to_string());
        naming_score -= 5.0;
    }

    // 2. Subscription name validation
    for sub in subscription_names {
        let mut sub_rule_failed = false;
        let sub_len = py_len(sub);
        if !(3 <= sub_len && sub_len <= 255) {
            subscription_issues.push(format!(
                "Subscription '{sub}' must be between 3 and 255 characters long."
            ));
            naming_score -= 25.0;
            sub_rule_failed = true;
        }

        if sub.is_empty() || !first_char_isalpha(sub) {
            subscription_issues.push(format!("Subscription '{sub}' must start with a letter."));
            naming_score -= 25.0;
            sub_rule_failed = true;
        }

        if !py_match_class(sub, topic_char_ok) {
            subscription_issues
                .push(format!("Subscription '{sub}' contains invalid characters."));
            naming_score -= 25.0;
            sub_rule_failed = true;
        }

        // Convention: Should end with '-sub', '-subscription', or 'Subscription'
        if !sub_rule_failed {
            if !(sub.ends_with("-sub")
                || sub.ends_with("-subscription")
                || sub.ends_with("Subscription"))
            {
                subscription_issues.push(format!(
                    "Subscription '{sub}' does not follow naming convention suffixes (-sub, -subscription, Subscription)."
                ));
                naming_score -= 5.0;
            }
        }
    }

    // 3. Project ID validation if provided
    if !project_id.is_empty() {
        let pid_len = py_len(project_id);
        if !(6 <= pid_len && pid_len <= 30) || !project_id_matches(project_id) {
            topic_issues.push(format!("Project ID '{project_id}' is in an invalid format."));
            naming_score -= 10.0;
        }
    }

    naming_score = naming_score.max(0.0);
    let risk_score = 100.0 - naming_score;

    // is_valid is True only if there are no critical topic rule failures.
    let critical_count = topic_issues
        .iter()
        .filter(|issue| {
            let lower = issue.to_lowercase();
            lower.contains("must start with a letter")
                || lower.contains("between 3 and 255")
                || lower.contains("invalid characters")
                || lower.contains("reserved 'goog'")
        })
        .count();
    let is_valid = critical_count == 0;

    let status = if !is_valid || risk_score > 60.0 {
        "FAIL".to_string()
    } else if risk_score >= 30.0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    Output {
        is_valid,
        topic_issues,
        subscription_issues,
        naming_score,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(topic: &str, subs: Vec<&str>, project: &str) -> Output {
        audit(&Input {
            topic_name: topic.to_string(),
            subscription_names: subs.into_iter().map(|s| s.to_string()).collect(),
            project_id: project.to_string(),
        })
    }

    #[test]
    fn clean_topic_passes() {
        let o = run("orders-events", vec!["orders-events-sub"], "my-project-1");
        assert!(o.is_valid);
        assert_eq!(o.status, "PASS");
        assert_eq!(o.naming_score, 100.0);
        assert_eq!(o.risk_score, 0.0);
        assert!(o.topic_issues.is_empty());
        assert!(o.subscription_issues.is_empty());
    }

    #[test]
    fn goog_prefix_and_invalid_chars_fail() {
        // starts with 'goog', has invalid char '@', and length ok
        let o = run("goog@bad", vec![], "");
        assert!(!o.is_valid);
        assert_eq!(o.status, "FAIL");
        // invalid chars (-25) + goog (-25) = 50 deducted
        assert_eq!(o.naming_score, 50.0);
        assert_eq!(o.risk_score, 50.0);
    }

    #[test]
    fn placeholder_keyword_warns_but_valid() {
        // contains "test" -> -5 only, risk 5.0 < 30 -> PASS, still valid
        let o = run("orders-test", vec![], "");
        assert!(o.is_valid);
        assert_eq!(o.naming_score, 95.0);
        assert_eq!(o.risk_score, 5.0);
        assert_eq!(o.status, "PASS");
    }

    #[test]
    fn subscription_convention_warning() {
        let o = run("orders-events", vec!["badname"], "");
        assert!(o.is_valid);
        assert_eq!(o.subscription_issues.len(), 1);
        assert_eq!(o.naming_score, 95.0);
        assert_eq!(o.status, "PASS");
    }

    #[test]
    fn trailing_newline_topic_matches_class() {
        // Python `$` allows a single trailing newline, so chars are "valid".
        let o = run("orders\n", vec![], "");
        // length is 7 (3..=255 ok), starts with letter, class ok via trailing-nl rule,
        // not goog, no placeholder -> fully valid.
        assert!(o.is_valid);
        assert!(o.topic_issues.is_empty());
        assert_eq!(o.naming_score, 100.0);
    }
}
