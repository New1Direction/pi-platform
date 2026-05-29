//! Port of `pi_micro_agents/pi_solidity_reentrancy_mutex_sentry.py`.
//!
//! Specialized Web3 micro-agent that audits Solidity contracts for custom
//! boolean reentrancy mutex locks (`bool locked; ... locked = true;`) which are
//! gas-expensive and error-prone compared to a standardized `nonReentrant`
//! modifier or transient storage. Behaviour is a line-for-line mirror of the
//! Python original.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pydantic `MutexSentryInput`.
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

/// Pydantic `MutexSentryOutput`.
#[derive(Debug, Serialize, PartialEq)]
pub struct Output {
    pub is_secure: bool,
    pub vulnerable_functions: Vec<String>,
    pub flagged_findings: Vec<String>,
    pub risk_score: f64,
    pub status: String,
}

/// Mirrors the Python custom-boolean-lock declaration matcher:
/// `\bbool\s+(private|public|internal)?\s*(locked|inSwap|reentrancyLock)\b`.
///
/// Two capture groups, but Python only uses the truthiness of `re.search`, so
/// we only need a match test. No lookaround / backreferences are used, so this
/// translates 1:1 to the Rust `regex` crate (which supports `\b`).
static MUTEX_DECL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bbool\s+(private|public|internal)?\s*(locked|inSwap|reentrancyLock)\b").unwrap()
});

/// Mirrors the Python manual-toggle matcher:
/// `(locked|inSwap|reentrancyLock)\s*=\s*(true|false)`.
///
/// Again only the truthiness of `re.search` is consumed. No lookaround /
/// backreferences — direct 1:1 translation.
static MANUAL_TOGGLE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(locked|inSwap|reentrancyLock)\s*=\s*(true|false)").unwrap());

/// Mirrors `is_strict_mode()`.
///
/// Python first checks the env var `PI_MUTEX_SENTRY_STRICT_MODE`: if set,
/// returns `value.lower() == "true"`. If unset, it falls back to a
/// `~/.antigravitycli/config.json` config file (or a module-relative
/// `../../.antigravitycli/config.json`), returning
/// `bool(data.get("PI_MUTEX_SENTRY_STRICT_MODE", True))` — i.e. defaulting to
/// `True` when the file is absent / unreadable / missing the key. We mirror the
/// env-var branch exactly and default to `true` when the env var is unset,
/// matching the Python default for a config file that lacks the key. See module
/// `deviations` notes for the config-file edge case.
fn is_strict_mode() -> bool {
    match std::env::var("PI_MUTEX_SENTRY_STRICT_MODE") {
        Ok(v) => v.to_lowercase() == "true",
        Err(_) => true,
    }
}

pub fn audit_mutex(input: &Input) -> Output {
    let code = &input.solidity_code;
    let mut vulnerable_funcs: Vec<String> = Vec::new();
    let mut flagged_findings: Vec<String> = Vec::new();

    // Find state variable declaration of custom boolean locks.
    let mutex_decl_match = MUTEX_DECL.is_match(code);

    if mutex_decl_match {
        // Found custom rolled boolean reentrancy locks.
        // Mode 1: Check if they toggle it manually using a boolean state variable.
        let manual_toggle_match = MANUAL_TOGGLE.is_match(code);

        if manual_toggle_match {
            vulnerable_funcs.push("file_header".to_string());
            flagged_findings.push(
                "Solidity contract declares a custom boolean reentrancy mutex: 'bool locked;'. \
Custom boolean locks are expensive and highly prone to developer error (e.g. forgot to reset in fallback, \
or missing try/catch safety). Use a standardized modifier 'nonReentrant' or modern transient storage instead."
                    .to_string(),
            );
        }
    }

    let mut is_secure = vulnerable_funcs.is_empty();
    let risk_score = if !is_secure { 80.0 } else { 0.0 };

    let is_strict = is_strict_mode();
    let mut status = "PASSED".to_string();
    if !is_secure {
        if is_strict {
            status = "REJECTED_MUTEX_RISK".to_string();
        } else {
            status = "WARN_MUTEX_RISK".to_string();
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
    let out = audit_mutex(&input);
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &str) -> Output {
        audit_mutex(&Input {
            file_path: "C.sol".into(),
            solidity_code: code.into(),
            check_level: "STRICT".into(),
        })
    }

    #[test]
    fn clean_contract_passes() {
        let o = run("contract C { function f() external nonReentrant {} }");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
        assert!(o.vulnerable_functions.is_empty());
        assert!(o.flagged_findings.is_empty());
    }

    #[test]
    fn custom_bool_mutex_flagged() {
        let o = run("bool private locked;\nfunction f() external { locked = true; _; locked = false; }");
        assert!(!o.is_secure);
        assert_eq!(o.status, "REJECTED_MUTEX_RISK");
        assert_eq!(o.risk_score, 80.0);
        assert_eq!(o.vulnerable_functions, vec!["file_header"]);
        assert_eq!(o.flagged_findings.len(), 1);
    }

    #[test]
    fn declared_but_never_toggled_passes() {
        // Declaration matches but no `locked = true/false` toggle -> secure.
        let o = run("bool public locked;");
        assert!(o.is_secure);
        assert_eq!(o.status, "PASSED");
        assert_eq!(o.risk_score, 0.0);
    }
}
