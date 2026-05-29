//! Port of `pi_micro_agents/pi_solidity_reentrancy_guard_overlap_sentry.py`.
//!
//! Audits Solidity contracts for functions carrying overlapping or redundant
//! reentrancy-guard modifiers. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub file_path: String,
    pub solidity_code: String,
    #[serde(default = "default_check_level")]
    pub check_level: String,
}

fn default_check_level() -> String {
    "STRICT".to_string()
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// `re.finditer(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)([^{]*)\{', code)`.
///
/// Python's `.` does not match newlines (no DOTALL) and the Rust `regex` crate
/// also leaves `.` non-newline-matching by default, so the two engines agree.
static FUNC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)([^{]*)\{").unwrap());

const REENTRANCY_KEYWORDS: [&str; 5] = [
    "nonReentrant",
    "noReentrancy",
    "lock",
    "mutex",
    "prevReentrant",
];

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
fn is_strict_mode() -> bool {
    match std::env::var("PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

/// Reproduces Python's `repr()` of a `list[str]` for the simple identifier
/// keywords used here, e.g. `['nonReentrant', 'lock']`. All keywords are plain
/// ASCII identifiers with no quotes/backslashes/control chars, so the repr is
/// always `'<kw>'` joined by `, ` inside square brackets.
fn py_list_repr(items: &[String]) -> String {
    let inner = items
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

pub fn audit_reentrancy_overlap(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find function declarations and modifiers
    for caps in FUNC_RE.captures_iter(code) {
        let func_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let attributes = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Check if there are multiple reentrancy-like modifiers
        let found_keywords: Vec<String> = REENTRANCY_KEYWORDS
            .iter()
            .filter(|kw| {
                // re.search(r'\b' + kw + r'\b', attributes)
                let pattern = format!(r"\b{}\b", regex::escape(kw));
                Regex::new(&pattern).unwrap().is_match(attributes)
            })
            .map(|kw| kw.to_string())
            .collect();

        if found_keywords.len() > 1 {
            vulnerable_funcs.push(func_name.to_string());
            flagged_findings.push(format!(
                "Function '{func_name}' has overlapping/redundant reentrancy guards: {}. \
This creates redundant state updates, increases gas consumption, and risks deadlocks or unexpected execution failures.",
                py_list_repr(&found_keywords)
            ));
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 65.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_REENTRANCY_GUARD_OVERLAP".to_string();
        } else {
            status = "WARN_REENTRANCY_GUARD_OVERLAP".to_string();
            is_secure = true;
        }
    }

    Output {
        is_secure,
        vulnerable_functions: vulnerable_funcs,
        flagged_findings,
        risk_score,
        status,
    }
}

pub fn run_json(input_json: &str) -> Result<String, String> {
    let input: Input = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let out = audit_reentrancy_overlap(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_reentrancy_overlap(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_single_guard_passes() {
        let o = run("function withdraw() external nonReentrant {\n  // ok\n}");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
    }

    #[test]
    fn overlapping_guards_flagged() {
        let o = run("function withdraw() external nonReentrant lock {\n  // bad\n}");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_REENTRANCY_GUARD_OVERLAP");
        assert_eq!(o.risk_score, 65.0);
        assert_eq!(o.vulnerable_functions, vec!["withdraw"]);
        assert!(o.flagged_findings[0].contains("['nonReentrant', 'lock']"));
    }

    #[test]
    fn no_function_decls_passes() {
        let o = run("");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert!(o.flagged_findings.is_empty());
    }
}
