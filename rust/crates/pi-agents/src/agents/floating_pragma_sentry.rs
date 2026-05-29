//! Port of `pi_micro_agents/pi_floating_pragma_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for floating or
//! unsafe compiler pragmas. Behaviour is a line-for-line mirror of the Python
//! original.

use crate::pyutil;
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

/// Mirrors `re.findall(r'pragma\s+solidity\s+([^;]+);', code)`.
/// One capture group, no lookaround / backrefs, so it maps directly.
/// `[^;]` matches newlines in both Python and the Rust `regex` crate, so a
/// pragma whose semicolon falls on a later line still matches identically.
static PRAGMA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"pragma\s+solidity\s+([^;]+);").unwrap());

/// Mirrors `re.search(r'(\d+\.\d+\.\d+)', pragma_val_clean)`.
static VERSION_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+\.\d+)").unwrap());

/// Mirrors `is_strict_mode()`: strict unless the env var is set to a value that
/// is not (case-insensitively) "true".
///
/// NOTE: the Python original ALSO falls back to a `~/.antigravitycli/config.json`
/// (or a repo-relative copy) file lookup when `PI_PRAGMA_STRICT_MODE` is unset,
/// defaulting to `True` if the file is absent / unreadable / does not set the
/// key. This port mirrors only the env-var branch (the established convention in
/// this codebase, e.g. `jwt_none_sentry.rs`) and defaults to strict (`true`)
/// when the env var is absent. See `deviations`.
fn is_strict_mode() -> bool {
    match std::env::var("PI_PRAGMA_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_pragma(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find all occurrences of pragma solidity (group 1 of each match).
    let pragma_matches: Vec<String> = PRAGMA_RE
        .captures_iter(code)
        .map(|c| c[1].to_string())
        .collect();

    if pragma_matches.is_empty() {
        vulnerable_funcs.push("file_header".to_string());
        flagged_findings.push(
            "Solidity file does not specify any 'pragma solidity' version. \
This leaves compiler choice completely unbound and highly unsafe."
                .to_string(),
        );
    } else {
        for pragma_val in &pragma_matches {
            let pragma_val_clean = pyutil::strip(pragma_val);

            // Mode 1: Floating Pragma Scan
            // A pragma is floating if it contains ^, >=, >, <=, < or does not
            // lock a single specific version.
            let mut is_floating = false;
            if ["^", ">", "<", ">=", "<="]
                .iter()
                .any(|op| pragma_val_clean.contains(op))
            {
                is_floating = true;
            }

            if is_floating {
                vulnerable_funcs.push("file_header".to_string());
                flagged_findings.push(format!(
                    "Solidity file uses a floating or unbounded pragma: 'pragma solidity {pragma_val_clean};'. \
Floating pragmas allow compilation with untested/buggy compilers in production."
                ));
            }

            // Mode 2: Locked Stable Pragma Auditor
            // Ensure the locked version is stable and not known to be severely
            // buggy or excessively outdated (e.g. <0.8.0).
            if let Some(version_match) = VERSION_RE.captures(pragma_val_clean) {
                let version_str = version_match[1].to_string();
                let parts: Vec<i64> = version_str
                    .split('.')
                    .map(|p| p.parse::<i64>().unwrap())
                    .collect();
                if parts.len() >= 3 {
                    let (major, minor, patch) = (parts[0], parts[1], parts[2]);
                    if major == 0 && minor < 8 {
                        flagged_findings.push(format!(
                            "Locked compiler version '{version_str}' is outdated and below 0.8.0. \
Deploying with old compiler versions risks encountering known compiler bugs (e.g. storage overflow issues)."
                        ));
                    }
                    // Specific known highly buggy compiler version check
                    // (e.g., 0.8.0 - 0.8.2 which had serious bugs).
                    if major == 0 && minor == 8 && (patch == 0 || patch == 1 || patch == 2) {
                        flagged_findings.push(format!(
                            "Compiler version '{version_str}' contains severe known code generation bugs (e.g., ABI encoder v2 bugs). \
Consider upgrading to at least 0.8.20."
                        ));
                    }
                }
            }
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_PRAGMA_RISK".to_string();
        } else {
            status = "WARN_PRAGMA_RISK".to_string();
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
    let out = audit_pragma(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn run(code: &str) -> Output {
        audit_pragma(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    #[serial]
    fn locked_stable_pragma_passes() {
        std::env::remove_var("PI_PRAGMA_STRICT_MODE");
        let o = run("pragma solidity 0.8.19;");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    #[serial]
    fn floating_pragma_rejected_in_strict_mode() {
        std::env::set_var("PI_PRAGMA_STRICT_MODE", "true");
        let o = run("pragma solidity ^0.8.0;");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_PRAGMA_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["file_header"]);
        // floating finding + buggy-version 0.8.0 finding
        assert_eq!(o.flagged_findings.len(), 2);
        std::env::remove_var("PI_PRAGMA_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn no_pragma_warns_in_non_strict_mode() {
        std::env::set_var("PI_PRAGMA_STRICT_MODE", "false");
        let o = run("contract C {}");
        // non-strict coerces is_secure back to true
        assert!(o.is_secure);
        assert_eq!(o.status, "WARN_PRAGMA_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["file_header"]);
        std::env::remove_var("PI_PRAGMA_STRICT_MODE");
    }

    #[test]
    #[serial]
    fn outdated_version_flagged() {
        std::env::remove_var("PI_PRAGMA_STRICT_MODE");
        let o = run("pragma solidity 0.7.6;");
        // locked single version => not floating => no vulnerable_functions
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        // outdated (<0.8.0) finding present even though secure
        assert_eq!(o.flagged_findings.len(), 1);
        assert!(o.flagged_findings[0].contains("below 0.8.0"));
    }
}
